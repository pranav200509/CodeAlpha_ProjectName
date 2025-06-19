from flask import Flask, request, session, redirect
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import timedelta
from contextlib import closing

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
csrf = CSRFProtect(app)

# Security configurations
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

def get_db():
    return sqlite3.connect("database.db")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Input validation
    if not (4 <= len(username) <= 25) or len(password) < 8:
        return "Invalid input", 400

    hashed_pw = generate_password_hash(password)

    try:
        with closing(get_db()) as conn:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)", 
                (username, hashed_pw)
            )
            conn.commit()
        return "Registered successfully", 201
    except sqlite3.IntegrityError:
        return "Username exists", 400

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with closing(get_db()) as conn:
        row = conn.execute(
            "SELECT password FROM users WHERE username = ?", 
            (username,)
        ).fetchone()

    if row and check_password_hash(row[0], password):
        session["user"] = username
        return redirect("/dashboard")
    return "Invalid credentials", 401

if __name__ == "__main__":
    app.run(debug=False)
