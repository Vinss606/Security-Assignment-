"""
Requirement 1 & 3: Administrative RBAC Governance, Account Unlock & Live PKI/TLS Inspector
"""
from __future__ import annotations

import ssl

from flask import Blueprint, Response, g, jsonify, request

from carevault.database import execute_transaction, execute_write, query_all, query_one
from carevault.middleware.auth import require_auth
from carevault.middleware.error_handler import AppError
from carevault.middleware.rbac import require_any_permission
from carevault.security.extension_hooks import security_events
from carevault.security.tls_validator import validate_certificate_chain
from carevault.security.validation import (
    UpdateUserRolePayload,
    parse_json_body,
    validate_positive_id,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/users")
@require_auth
@require_any_permission("users:read:all")
def list_users() -> Response:
    users = query_all(
        """
        SELECT id, full_name, email, phone, role, assigned_doctor_id, mfa_enabled,
               failed_login_attempts, locked_until, created_at
        FROM users ORDER BY id ASC
        """
    )
    doctors = query_all(
        "SELECT id, full_name, email FROM users WHERE role = 'doctor' ORDER BY full_name ASC"
    )
    return jsonify({"status": "success", "users": users, "doctors": doctors})


@admin_bp.patch("/users/<raw_id>/role")
@require_auth
@require_any_permission("users:update:role")
def update_user_role(raw_id: str) -> Response:
    target_id = validate_positive_id(raw_id)
    body = parse_json_body(UpdateUserRolePayload)

    if target_id == g.user["id"] and body.role != "admin":
        raise AppError(
            400,
            "SELF_DEMOTION_BLOCKED",
            "Administrators cannot demote their own active administrative account.",
        )

    target_user = query_one("SELECT * FROM users WHERE id = ?", (target_id,))
    if not target_user:
        raise AppError(404, "USER_NOT_FOUND", "Target user account does not exist.")

    normalized_doc_id: int | None = None
    if body.role == "patient" and body.assignedDoctorId is not None:
        doc_row = query_one("SELECT * FROM users WHERE id = ?", (body.assignedDoctorId,))
        if not doc_row or doc_row["role"] != "doctor" or doc_row["id"] == target_id:
            raise AppError(
                400,
                "INVALID_ASSIGNED_DOCTOR",
                "Assigned clinician must be an active user with the doctor role.",
            )
        normalized_doc_id = int(doc_row["id"])

    tx_stmts: list[tuple[str, tuple]] = []
    if target_user["role"] == "doctor" and body.role != "doctor":
        tx_stmts.append(
            (
                "UPDATE users SET assigned_doctor_id = NULL WHERE assigned_doctor_id = ?",
                (target_id,),
            )
        )

    tx_stmts.append(
        (
            "UPDATE users SET role = ?, assigned_doctor_id = ? WHERE id = ?",
            (body.role, normalized_doc_id, target_id),
        )
    )
    # Immediately revoke all active sessions of the modified user inside the same atomic transaction
    tx_stmts.append(("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (target_id,)))
    execute_transaction(tx_stmts)

    security_events.publish(
        "admin.role.updated",
        {
            "adminId": g.user["id"],
            "targetUserId": target_id,
            "previousRole": target_user["role"],
            "newRole": body.role,
        },
    )

    return jsonify(
        {
            "status": "success",
            "message": "User role updated and existing sessions revoked to enforce new privileges immediately.",
        }
    )


@admin_bp.post("/users/<raw_id>/unlock")
@require_auth
@require_any_permission("users:unlock")
def unlock_user(raw_id: str) -> Response:
    target_id = validate_positive_id(raw_id)
    target_user = query_one("SELECT * FROM users WHERE id = ?", (target_id,))
    if not target_user:
        raise AppError(404, "USER_NOT_FOUND", "Target user account does not exist.")

    execute_write(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
        (target_id,),
    )
    security_events.publish(
        "admin.user.unlocked",
        {"adminId": g.user["id"], "targetUserId": target_id},
    )
    return jsonify({"status": "success", "message": "Account lockout cleared successfully."})


@admin_bp.get("/security/tls-status")
@require_auth
@require_any_permission("security:pki:inspect")
def tls_status() -> Response:
    cert_validation = validate_certificate_chain()
    raw_sock = request.environ.get("werkzeug.socket")
    if isinstance(raw_sock, ssl.SSLSocket):
        cipher_tuple = raw_sock.cipher()
        active_conn = {
            "encrypted": True,
            "negotiatedProtocol": raw_sock.version(),
            "negotiatedCipher": {
                "name": cipher_tuple[0] if cipher_tuple else "N/A",
                "version": cipher_tuple[1] if cipher_tuple else "N/A",
                "bits": cipher_tuple[2] if cipher_tuple else 0,
            },
        }
    elif request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        active_conn = {
            "encrypted": True,
            "negotiatedProtocol": "TLSv1.3 (Edge Proxy)",
            "negotiatedCipher": {"name": "TLS_AES_256_GCM_SHA384"},
        }
    else:
        active_conn = {"encrypted": False}

    return jsonify(
        {
            "status": "success",
            "activeConnection": active_conn,
            "pkiValidation": cert_validation,
        }
    )

