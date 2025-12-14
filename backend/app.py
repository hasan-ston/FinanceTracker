import os
from datetime import datetime, timedelta
from random import randint

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

# Single-file Flask app to keep things simple.
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///finance.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})


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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(255))
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


@app.post("/api/auth/register")
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
def login():
    data = request.get_json() or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": token, "user": {"id": user.id, "email": user.email}})


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
    expenses = Expense.query.filter_by(user_id=user_id).all()
    summary = {}
    for exp in expenses:
        summary[exp.category] = summary.get(exp.category, 0) + float(exp.amount)
    return jsonify({"summary": [{"category": c, "total": t} for c, t in summary.items()]})


@app.post("/api/imports/mock")
@jwt_required()
def import_mock():
    user_id = int(get_jwt_identity())
    created = []
    base_time = datetime.utcnow()
    categories = ["groceries", "transportation", "entertainment", "rent", "other"]
    for idx in range(5):
        amount = round(randint(5, 300) + randint(0, 99) / 100, 2)
        exp = Expense(
            user_id=user_id,
            category=categories[idx % len(categories)],
            description=f"Mock transaction {idx + 1}",
            amount=float(amount),
            created_at=base_time - timedelta(days=idx),
        )
        db.session.add(exp)
        created.append(exp)
    db.session.commit()
    return jsonify({"imported": len(created), "expenses": [e.id for e in created]})


@app.get("/healthz")
def health():
    return jsonify({"status": "ok"})


def _serialize(exp):
    return {
        "id": exp.id,
        "category": exp.category,
        "description": exp.description,
        "amount": float(exp.amount),
        "created_at": exp.created_at.isoformat(),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
