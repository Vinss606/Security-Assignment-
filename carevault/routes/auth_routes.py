"""
Insecure Authentication Routes (carevault/routes/auth_routes.py)
INTENTIONALLY VULNERABLE BASELINE:
- SQL Injection in Login endpoint (CWE-89)
- Mass Assignment in Registration endpoint (CWE-915)
- User Enumeration via verbose error messages (CWE-204)
- Missing Account Lockout / Unlimited Brute Force (CWE-307)
- Insecure session cookie: No HttpOnly, No Secure, SameSite=None (CWE-1004 / CWE-614)
"""
from __future__ import annotations

import secrets
from typing import Any
from flask import Blueprint, Response, jsonify, request, make_response

from carevault.database import raw_query_one, raw_execute_write, weak_md5_hash

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def get_current_user(req: Any) -> dict[str, Any] | None:
    session_id = req.cookies.get("cv_insecure_session")
    if not session_id:
        return None
    try:
        session = raw_query_one(f"SELECT * FROM sessions WHERE session_id = '{session_id}'")
        if not session:
            return None
        user = raw_query_one(f"SELECT * FROM users WHERE id = {session['user_id']}")
        return user
    except Exception:
        return None


@auth_bp.post("/login")
def login() -> Response:
    data = request.get_json(silent=True) or request.form.to_dict()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # VULNERABILITY: SQL Injection via direct string formatting in SQL query
    pwd_hash = weak_md5_hash(password)
    # If the attacker supplies `' OR '1'='1' --` in email, the query matches immediately!
    sql = f"SELECT * FROM users WHERE email = '{email}' AND password_hash = '{pwd_hash}'"

    # Also: User enumeration flaw
    user_check = raw_query_one(f"SELECT * FROM users WHERE email = '{email}'")
    if not user_check and "' OR '" not in email:
        # Leaks whether the email exists in the database
        return jsonify({"error": "User with this email does not exist"}), 400

    user = raw_query_one(sql)
    if not user:
        return jsonify({"error": "Incorrect password"}), 401

    # VULNERABILITY: No Account Lockout (failed_login_attempts not enforced)
    # VULNERABILITY: No Multi-Factor Authentication (TOTP 2FA omitted)

    session_id = secrets.token_hex(16)
    raw_execute_write(f"INSERT INTO sessions (session_id, user_id) VALUES ('{session_id}', {user['id']})")

    resp = make_response(
        jsonify(
            {
                "status": "ok",
                "message": f"Welcome back, {user['full_name']}",
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "fullName": user["full_name"],
                    "role": user["role"],
                },
            }
        )
    )

    # VULNERABILITY: Insecure cookie lacking HttpOnly and Secure flags!
    # Accessible to document.cookie in JavaScript (enabling session theft via XSS)
    resp.set_cookie(
        "cv_insecure_session",
        session_id,
        path="/",
        httponly=False,  # Vulnerable: JavaScript can read this!
        secure=False,    # Vulnerable: Sent over plaintext HTTP
        samesite=None,   # Vulnerable: Subject to CSRF
    )
    return resp


@auth_bp.post("/register")
def register() -> Response:
    data = request.get_json(silent=True) or request.form.to_dict()
    email = data.get("email", "").strip()
    full_name = data.get("fullName", "").strip()
    phone = data.get("phone", "").strip()
    password = data.get("password", "")

    # VULNERABILITY: Mass Assignment / Privilege Escalation
    # Directly trusts client-provided role! Anyone passing {"role": "admin"} becomes Administrator!
    role = data.get("role", "patient")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # VULNERABILITY: Weak Password Policy (Accepts passwords like '123' or 'a')
    if len(password) < 1:
        return jsonify({"error": "Password cannot be empty"}), 400

    # Check for duplicate
    existing = raw_query_one(f"SELECT * FROM users WHERE email = '{email}'")
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    pwd_hash = weak_md5_hash(password)
    # VULNERABILITY: SQL Injection via unescaped string formatting
    sql = (
        f"INSERT INTO users (full_name, email, phone, password_hash, role) "
        f"VALUES ('{full_name}', '{email}', '{phone}', '{pwd_hash}', '{role}')"
    )
    try:
        user_id = raw_execute_write(sql)
    except Exception as e:
        return jsonify({"error": f"Database syntax error: {str(e)}"}), 500

    return jsonify(
        {
            "status": "ok",
            "message": "User registered successfully",
            "user": {
                "id": user_id,
                "email": email,
                "fullName": full_name,
                "role": role,
            },
        }
    ), 201


@auth_bp.post("/logout")
def logout() -> Response:
    session_id = request.cookies.get("cv_insecure_session")
    if session_id:
        raw_execute_write(f"DELETE FROM sessions WHERE session_id = '{session_id}'")
    resp = make_response(jsonify({"status": "ok", "message": "Logged out"}))
    resp.delete_cookie("cv_insecure_session")
    return resp

