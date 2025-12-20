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
from openai import OpenAI
import redis
from werkzeug.security import check_password_hash, generate_password_hash

# Single-file Flask app to keep things simple.
app = Flask(__name__) # Creating flask instance
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")
_db_url = os.getenv("DATABASE_URL", "sqlite:///finance.db")
if _db_url.startswith("postgresql://"):
    _db_url = _db_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REDIS_URL"] = os.getenv("REDIS_URL", "redis://localhost:6379/0")
app.config["RATELIMIT_STORAGE_URI"] = os.getenv("RATELIMIT_STORAGE_URI", app.config["REDIS_URL"])
db = SQLAlchemy(app)
jwt = JWTManager(app) # This sets up JWT functionality in the app. This reads JWT_SECRET_KEY, sets up @jwt_required(), configures token verification, and prepares default error handlers.
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    default_limits=["200 per hour"],
)

redis_client = redis.from_url(app.config["REDIS_URL"], decode_responses=True)
openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY")) if os.getenv("OPENAI_API_KEY") else None
CORS(app, resources={r"/api/*": {"origins": "*"}})


# User model 
class User(db.Model): # User represents the users table in database
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
    db.create_all() # creates all tables by models (user + expense)


@app.post("/api/auth/register")
@limiter.limit("5 per minute")
def register():
    data = request.get_json() or {} # fallback incase user enters wrong input, data is always a dictionary.
    # data = {"email": "alice@example.com", "password": "password123"}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400 # jsonify converts python dict to JSON response
        # The ',' creates a tuple that Flask understands as (reponse_body, status_code)
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 409

    user = User(email=email) # Creates user instance
    user.set_password(password) # this automatically passes that instance as self
    db.session.add(user)
    db.session.commit() 

    token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": token, "user": {"id": user.id, "email": user.email}}), 201


@app.post("/api/auth/login") # when someone visits this url, run this function 
@limiter.limit("10 per minute")
def login():
    data = request.get_json() or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # Find user in db
    user = User.query.filter_by(email=email).first() # Database query on users table searching for this specific email and returning the first matching user 
    # Check password
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

    # Creating a new expense object
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
    # 


@app.get("/api/expenses")
@jwt_required()
def list_expenses():
    user_id = int(get_jwt_identity()) # this extracts user.id from JWT token
    expenses = ( # a list of Expense objects
        Expense.query.filter_by(user_id=user_id)
        .order_by(Expense.created_at.desc())
        .limit(100)
        .all()
    )
    return jsonify({"expenses": [_serialize(e) for e in expenses]}) # this resuls in a list of dictionaries which jsonify coverts to a JSON HTTP response.
# Client recieves JSON object.

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
    if not openai_client:
        return jsonify({"error": "AI insights unavailable. OPENAI_API_KEY not configured."}), 503

    user_id = int(get_jwt_identity())
    summary_list = _compute_summary_list(user_id)
    if not summary_list:
        return jsonify({"insight": "Add some expenses to get insights."})

    try:
        prompt = (
            "You are a concise finance assistant. Given category totals, provide 3 short, practical insights. "
            "Avoid jargon. Data: "
            + "; ".join(f"{item['category']}: {item['total']}" for item in summary_list)
        )
        
        print(f"Making OpenAI request for user {user_id}")  # Debug log
        
        resp = openai_client.chat.completions.create(
            model="gpt-4o-mini",  # Use the newer, cheaper model
            messages=[
                {"role": "system", "content": "Keep responses brief and actionable."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=180,
            temperature=0.4,
        )
        insight_text = resp.choices[0].message.content.strip()
        return jsonify({"insight": insight_text, "summary": summary_list})
        
    except Exception as e:
        error_msg = str(e)
        print(f"OpenAI API error: {error_msg}")  # This shows in Render logs
        
        # Return user-friendly error
        if "insufficient_quota" in error_msg:
            return jsonify({"error": "OpenAI API quota exceeded. Please check your billing."}), 502
        elif "invalid_api_key" in error_msg:
            return jsonify({"error": "Invalid OpenAI API key configured."}), 502
        else:
            return jsonify({"error": f"AI service temporarily unavailable: {error_msg}"}), 502


@app.get("/healthz")
def health():
    return jsonify({"status": "ok"})

# Builds a simple per-category summary for a user.
def _compute_summary_list(user_id: int):
    expenses = Expense.query.filter_by(user_id=user_id).all()
    summary = {}
    for exp in expenses:
        summary[exp.category] = summary.get(exp.category, 0) + float(exp.amount)
    return [{"category": c, "total": t} for c, t in summary.items()]

# Turns the expense object into dict ready for JSON
def _serialize(exp):
    return {
        "id": exp.id,
        "category": exp.category,
        "description": exp.description,
        "amount": float(exp.amount),
        "created_at": exp.created_at.isoformat(),
    }


def _redis_get(key):
    try:
        raw = redis_client.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _redis_set(key, value, ttl=300):
    try:
        redis_client.setex(key, ttl, json.dumps(value))
    except Exception:
        pass


def _invalidate_summary_cache(user_id: int):
    try:
        redis_client.delete(f"summary:{user_id}")
    except Exception:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
