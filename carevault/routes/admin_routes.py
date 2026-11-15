"""
Insecure Admin Routes (carevault/routes/admin_routes.py)
INTENTIONALLY VULNERABLE BASELINE:
- Broken Access Control
- Missing CSRF protection on role change
"""
from __future__ import annotations

from flask import Blueprint, Response, jsonify, request

from carevault.database import raw_query_all, raw_execute_write
from carevault.routes.auth_routes import get_current_user

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/users")
def list_users() -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULNERABILITY: Weak RBAC check
    if user["role"] != "admin":
        return jsonify({"error": "Admin required"}), 403

    users = raw_query_all("SELECT id, full_name, email, phone, role, password_hash, created_at FROM users")
    return jsonify({"status": "ok", "users": users})


@admin_bp.post("/users/<int:target_user_id>/role")
def change_role(target_user_id: int) -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if user["role"] != "admin":
        return jsonify({"error": "Admin required"}), 403

    # VULNERABILITY: No CSRF verification!
    data = request.get_json(silent=True) or request.form.to_dict()
    new_role = data.get("role", "patient")
    raw_execute_write(f"UPDATE users SET role = '{new_role}' WHERE id = {target_user_id}")
    return jsonify({"status": "ok", "message": f"User {target_user_id} role updated to {new_role}"})

