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
import google.generativeai as genai
import redis
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
db = SQLAlchemy(app)
jwt = JWTManager(app)

redis_client = redis.from_url(app.config["REDIS_URL"], decode_responses=True)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    default_limits=["200 per hour"],
)

# Initialize Google Gemini
gemini_model = None
if os.getenv("GEMINI_API_KEY"):
    try:
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        gemini_model = genai.GenerativeModel('gemini-1.5-flash')
        print("Gemini AI initialized successfully")
    except Exception as e:
        print(f"Gemini initialization error: {e}")

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
    user_id = int(get_jwt_identity())
    cache_key = f"summary:{user_id}"
    cached = _redis_get(cache_key)
    if cached is not None:
        return jsonify({"summary": cached})

    summary_list = _compute_summary_list(user_id)
    _redis_set(cache_key, summary_list, ttl=300)
    return jsonify({"summary": summary_list})


@app.get("/api/expenses/insights")
@jwt_required()
@limiter.limit("3 per minute")
def expense_insights():
    user_id = int(get_jwt_identity())
    summary_list = _compute_summary_list(user_id)
    
    if not summary_list:
        return jsonify({"insight": "Add some expenses to get insights.", "summary": []})
    
    if not gemini_model:
        return jsonify({
            "insight": "AI insights temporarily unavailable. Here's your spending summary:",
            "summary": summary_list
        })

    try:
        prompt = (
            "You are a concise finance assistant. Given category totals, provide 3 short, practical insights. "
            "Avoid jargon. Keep it brief and actionable. Data: "
            + "; ".join(f"{item['category']}: ${item['total']:.2f}" for item in summary_list)
        )
        
        print(f"Making Gemini request for user {user_id}")
        
        response = gemini_model.generate_content(prompt)
        insight_text = response.text.strip()
        
        return jsonify({"insight": insight_text, "summary": summary_list})
        
    except Exception as e:
        error_msg = str(e)
        print(f"Gemini API error: {error_msg}")
        
        # Fallback: return summary without AI insights
        return jsonify({
            "insight": "AI insights temporarily unavailable. Your spending summary is shown below.",
            "summary": summary_list
        })


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
        return None
    try:
        raw = redis_client.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _redis_set(key, value, ttl=300):
    if not redis_client:
        return
    try:
        redis_client.setex(key, ttl, json.dumps(value))
    except Exception:
        pass


def _invalidate_summary_cache(user_id: int):
    if not redis_client:
        return
    try:
        redis_client.delete(f"summary:{user_id}")
    except Exception:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
