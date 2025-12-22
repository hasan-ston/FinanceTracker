import os
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
import json
from google import genai
import logging
from openai import OpenAI
import redis
import time
from werkzeug.security import check_password_hash, generate_password_hash

# Single-file Flask app to keep things simple.
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")
_db_url = os.getenv("DATABASE_URL", "sqlite:///finance.db")
# Prefer psycopg (v3) driver if using Postgres and no driver specified.
if _db_url.startswith("postgresql://"):
    _db_url = _db_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REDIS_URL"] = os.getenv("REDIS_URL", "redis://localhost:6379/0")
app.config["RATELIMIT_STORAGE_URI"] = os.getenv("RATELIMIT_STORAGE_URI", app.config["REDIS_URL"])
jw_logger = logging.getLogger("werkzeug")
jw_logger.setLevel(logging.WARNING)
logging.basicConfig(level=logging.INFO)

db = SQLAlchemy(app)
jwt = JWTManager(app)

def _init_redis(url: str):
    try:
        kwargs = {"decode_responses": True}
        if url.startswith("rediss://"):
            kwargs["ssl"] = True
            kwargs["ssl_cert_reqs"] = None
        client = redis.from_url(url, **kwargs)
        client.ping()
        app.logger.info("Redis connected")
        return client
    except Exception as exc:
        app.logger.warning("Redis disabled (init failed): %s", exc)
        return None


# Initialize AI providers
gemini_client = None
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash").strip()
_gemini_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
if _gemini_api_key:
    try:
        if GEMINI_MODEL.endswith("-latest"):
            GEMINI_MODEL = GEMINI_MODEL.replace("-latest", "")
        gemini_client = genai.Client(api_key=_gemini_api_key)
        app.logger.info("Gemini client initialized model=%s", GEMINI_MODEL)
    except Exception:
        app.logger.exception("Gemini initialization error")

openai_client = None
_openai_api_key = os.getenv("OPENAI_API_KEY")
if _openai_api_key:
    try:
        openai_client = OpenAI(api_key=_openai_api_key)
        app.logger.info("OpenAI client initialized")
    except Exception as exc:
        app.logger.error("OpenAI initialization error: %s", exc)

redis_client = _init_redis(app.config["REDIS_URL"])

limiter_storage = app.config["RATELIMIT_STORAGE_URI"] if redis_client else "memory://"
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=limiter_storage,
    default_limits=["200 per hour"],
)

CORS(app, resources={r"/api/*": {"origins": "*"}})


# User model 
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Expense(db.Model):
    __tablename__ = "expenses"
    __table_args__ = (db.Index("ix_expenses_user_created", "user_id", "created_at"),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(255))
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


with app.app_context():
    db.create_all()


@app.get("/")
def home():
    return jsonify({"status": "ok", "message": "Finance API running"})


@app.post("/api/auth/register")
@limiter.limit("5 per minute")
def register():
    data = request.get_json() or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 409

    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit() 

    token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": token, "user": {"id": user.id, "email": user.email}}), 201


@app.post("/api/auth/login")
@limiter.limit("10 per minute")
def login():
    data = request.get_json() or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": token, 
        "user": {"id": user.id, "email": user.email}
    })


@app.post("/api/expenses")
@jwt_required()
def create_expense():
    data = request.get_json() or {}
    category = data.get("category")
    description = data.get("description", "")
    amount = data.get("amount")
    if not category or amount is None:
        return jsonify({"error": "Category and amount required"}), 400

    exp = Expense(
        user_id=int(get_jwt_identity()),
        category=category,
        description=description,
        amount=float(amount),
    )
    db.session.add(exp)
    db.session.commit()
    _invalidate_summary_cache(int(get_jwt_identity()))
    return jsonify({"expense": _serialize(exp)}), 201


@app.delete("/api/expenses/<int:expense_id>")
@jwt_required()
def delete_expense(expense_id: int):
    user_id = int(get_jwt_identity())
    exp = Expense.query.filter_by(id=expense_id, user_id=user_id).first()
    if not exp:
        return jsonify({"error": "Expense not found"}), 404
    db.session.delete(exp)
    db.session.commit()
    _invalidate_summary_cache(user_id)
    return jsonify({"message": "Expense deleted"})


@app.get("/api/expenses")
@jwt_required()
def list_expenses():
    user_id = int(get_jwt_identity())
    expenses = (
        Expense.query.filter_by(user_id=user_id)
        .order_by(Expense.created_at.desc())
        .limit(100)
        .all()
    )
    return jsonify({"expenses": [_serialize(e) for e in expenses]})


@app.get("/api/expenses/summary")
@jwt_required()
def expense_summary():
    start = time.perf_counter()
    user_id = int(get_jwt_identity())
    cache_key = f"summary:{user_id}"
    cached = _redis_get(cache_key)
    if cached is not None:
        duration_ms = (time.perf_counter() - start) * 1000
        app.logger.info("summary cache_hit user=%s items=%s duration_ms=%.2f", user_id, len(cached), duration_ms)
        return jsonify({"summary": cached})

    summary_list = _compute_summary_list(user_id)
    _redis_set(cache_key, summary_list, ttl=300)
    duration_ms = (time.perf_counter() - start) * 1000
    app.logger.info("summary cache_miss user=%s items=%s duration_ms=%.2f", user_id, len(summary_list), duration_ms)
    return jsonify({"summary": summary_list})


@app.get("/api/expenses/insights")
@jwt_required()
@limiter.limit("3 per minute")
def expense_insights():
    user_id = int(get_jwt_identity())
    summary_list = _compute_summary_list(user_id)
    
    if not summary_list:
        return jsonify({"insight": "Add some expenses to get insights.", "summary": []})

    insight_text, warning, provider = _generate_insight(summary_list)
    app.logger.info("insights provider=%s user=%s items=%s warning=%s", provider, user_id, len(summary_list), bool(warning))
    response_body = {"insight": insight_text, "summary": summary_list}
    if warning:
        response_body["warning"] = warning
    return jsonify(response_body)


@app.get("/healthz")
def health():
    return jsonify({"status": "ok"})


def _compute_summary_list(user_id: int):
    expenses = Expense.query.filter_by(user_id=user_id).all()
    summary = {}
    for exp in expenses:
        summary[exp.category] = summary.get(exp.category, 0) + float(exp.amount)
    return [{"category": c, "total": t} for c, t in summary.items()]


def _serialize(exp):
    return {
        "id": exp.id,
        "category": exp.category,
        "description": exp.description,
        "amount": float(exp.amount),
        "created_at": exp.created_at.isoformat(),
    }


def _redis_get(key):
    if not redis_client:
        app.logger.info("redis_get skipped (no redis client)")
        return None
    try:
        raw = redis_client.get(key)
        return json.loads(raw) if raw else None
    except Exception as exc:
        app.logger.warning("redis_get error: %s", exc)
        return None


def _redis_set(key, value, ttl=300):
    if not redis_client:
        app.logger.info("redis_set skipped (no redis client)")
        return
    try:
        redis_client.setex(key, ttl, json.dumps(value))
    except Exception as exc:
        app.logger.warning("redis_set error: %s", exc)


def _invalidate_summary_cache(user_id: int):
    if not redis_client:
        return
    try:
        redis_client.delete(f"summary:{user_id}")
    except Exception as exc:
        app.logger.warning("redis_delete error: %s", exc)


def _generate_insight(summary_list):
    """Try Gemini, then OpenAI; fall back to heuristics."""
    prompt = (
        "You are a concise finance assistant. Given category totals, provide 3 short, practical insights. "
        "Avoid jargon. Keep it brief and actionable. Data: "
        + "; ".join(f"{item['category']}: ${item['total']:.2f}" for item in summary_list)
    )

    errors = []

    if gemini_client:
        try:
            resp = gemini_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            text = (getattr(resp, "text", "") or "").strip()
            if text:
                return text, None, "gemini"
            errors.append("Gemini returned empty text")
        except Exception as exc:
            app.logger.exception("Gemini insight generation failed")
            errors.append(f"Gemini error: {exc}")

    if openai_client:
        try:
            resp = openai_client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=[
                    {"role": "system", "content": "Keep responses brief and actionable."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=180,
                temperature=0.4,
            )
            text = resp.choices[0].message.content.strip()
            if text:
                return text, None, "openai"
            errors.append("OpenAI returned empty text")
        except Exception as exc:
            app.logger.exception("OpenAI insight generation failed")
            errors.append(f"OpenAI error: {exc}")

    fallback = _fallback_insight(summary_list)
    warning = (
        "; ".join(errors)
        if errors
        else "AI insights unavailable; showing a quick heuristic summary instead."
    )
    return fallback, warning, "fallback"


def _fallback_insight(summary_list):
    if not summary_list:
        return "Add expenses to get a spending readout."
    sorted_list = sorted(summary_list, key=lambda x: x["total"], reverse=True)
    top = sorted_list[0]
    total_spend = sum(item["total"] for item in summary_list) or 1
    top_share = (top["total"] / total_spend) * 100

    tips = [
        f"Your biggest category is {top['category']} at {top_share:.0f}% of spend.",
        "Set a weekly cap for that category and check back after a few entries.",
    ]

    if len(sorted_list) > 1:
        second = sorted_list[1]
        tips.append(f"Next up: {second['category']} ({second['total']:.2f}). Consider trimming 5-10% there.")
    else:
        tips.append("Add more categories to see a fuller picture.")

    return " ".join(tips)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
