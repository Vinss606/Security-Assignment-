"""
Requirement 1: Authentication, Registration, Lockout & TOTP 2FA Routes
"""
from __future__ import annotations

import datetime as dt

from flask import Blueprint, Response, g, jsonify, make_response, request

from carevault.config import settings
from carevault.database import execute_write, query_all, query_one
from carevault.middleware.auth import clear_session_cookie, issue_session, require_auth
from carevault.middleware.error_handler import AppError
from carevault.middleware.rate_limiter import auth_rate_limit
from carevault.middleware.rbac import ROLE_PERMISSIONS
from carevault.security.extension_hooks import security_events
from carevault.security.password import (
    hash_password,
    validate_password_policy,
    verify_password,
)
from carevault.security.totp import (
    build_otpauth_qr,
    decrypt_secret,
    encrypt_secret,
    generate_totp_secret,
    verify_totp_code,
)
from carevault.security.validation import (
    LoginPayload,
    MfaDisablePayload,
    MfaVerifyPayload,
    RegisterPayload,
    parse_json_body,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _record_failed_attempt(user_row: dict, reason: str) -> None:
    now_utc = dt.datetime.now(dt.UTC)
    lockout_expired = False
    if user_row.get("locked_until"):
        locked_dt = dt.datetime.fromisoformat(user_row["locked_until"])
        if locked_dt <= now_utc:
            lockout_expired = True

    base_attempts = 0 if lockout_expired else int(user_row.get("failed_login_attempts") or 0)
    attempts = base_attempts + 1
    locked_until = None if lockout_expired else user_row.get("locked_until")

    if attempts >= settings.max_failed_login_attempts:
        locked_until = (
            now_utc + dt.timedelta(minutes=settings.account_lockout_minutes)
        ).isoformat()
        security_events.publish(
            "auth.account.locked",
            {
                "userId": user_row["id"],
                "email": user_row["email"],
                "ip": request.remote_addr,
                "lockedUntil": locked_until,
            },
        )

    execute_write(
        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
        (attempts, locked_until, user_row["id"]),
    )
    security_events.publish(
        "auth.login.failed",
        {
            "userId": user_row["id"],
            "ip": request.remote_addr,
            "reason": reason,
            "attempts": attempts,
        },
    )


@auth_bp.post("/register")
@auth_rate_limit
def register() -> tuple[Response, int]:
    body = parse_json_body(RegisterPayload)

    policy = validate_password_policy(body.password, [body.fullName, body.email])
    if not policy["valid"]:
        raise AppError(
            400,
            "WEAK_PASSWORD",
            "Password does not satisfy CareVault security policy.",
            [{"field": "password", "message": msg} for msg in policy["issues"]],
        )

    existing = query_one("SELECT id FROM users WHERE email = ?", (body.email,))
    if existing:
        raise AppError(
            409,
            "REGISTRATION_CONFLICT",
            "Unable to complete registration with the provided email address.",
        )

    pwd_hash = hash_password(body.password)
    doctors = query_all("SELECT id FROM users WHERE role = 'doctor' ORDER BY full_name ASC")
    default_doctor_id = doctors[0]["id"] if doctors else None

    # Principle of Least Privilege: Self-registration ALWAYS assigns 'patient' role
    user_id = execute_write(
        """
        INSERT INTO users (full_name, email, phone, password_hash, role, assigned_doctor_id)
        VALUES (?, ?, ?, ?, 'patient', ?)
        """,
        (body.fullName, body.email, body.phone, pwd_hash, default_doctor_id),
    )

    security_events.publish(
        "auth.user.registered",
        {"userId": user_id, "role": "patient", "ip": request.remote_addr},
    )

    return (
        jsonify(
            {
                "status": "success",
                "message": "Patient account created securely. You may now sign in.",
                "passwordEntropyBits": policy["entropyBits"],
            }
        ),
        201,
    )


@auth_bp.post("/login")
@auth_rate_limit
def login() -> Response | tuple[Response, int]:
    body = parse_json_body(LoginPayload)
    user_row = query_one("SELECT * FROM users WHERE email = ?", (body.email,))

    # Always run Argon2id verification even if user_row is None (anti-enumeration)
    password_valid = verify_password(
        user_row["password_hash"] if user_row else None,
        body.password,
    )

    if not user_row:
        security_events.publish(
            "auth.login.failed",
            {"userId": None, "ip": request.remote_addr, "reason": "unknown_identifier"},
        )
        raise AppError(401, "INVALID_CREDENTIALS", "Invalid email address or password.")

    now_utc = dt.datetime.now(dt.UTC)
    if user_row.get("locked_until"):
        locked_dt = dt.datetime.fromisoformat(user_row["locked_until"])
        if locked_dt > now_utc:
            security_events.publish(
                "auth.login.blocked_lockout",
                {"userId": user_row["id"], "ip": request.remote_addr},
            )
            raise AppError(
                423,
                "ACCOUNT_LOCKED",
                "This account is temporarily locked due to repeated failed sign-in attempts. Please try again later or contact an administrator.",
            )

    if not password_valid:
        _record_failed_attempt(user_row, "bad_password")
        raise AppError(401, "INVALID_CREDENTIALS", "Invalid email address or password.")

    # Enforce RFC 6238 TOTP Second Factor if enabled
    if user_row["mfa_enabled"] == 1 and user_row.get("mfa_secret_enc"):
        if not body.totpCode:
            return jsonify(
                {
                    "status": "mfa_required",
                    "message": "Primary credentials verified. Please enter your 6-digit Authenticator code.",
                }
            )
        raw_secret = decrypt_secret(user_row["mfa_secret_enc"])
        totp_result = verify_totp_code(
            raw_secret,
            body.totpCode,
            last_used_step=user_row.get("mfa_last_used_step"),
        )
        if not totp_result["valid"]:
            reason = "replayed_totp" if totp_result["replayed"] else "bad_totp"
            _record_failed_attempt(user_row, reason)
            msg = (
                "This 6-digit code was already used. Please wait for the next 30-second Authenticator code."
                if totp_result["replayed"]
                else "Invalid 6-digit Authenticator verification code."
            )
            raise AppError(401, "INVALID_MFA_CODE", msg)

        execute_write(
            "UPDATE users SET mfa_last_used_step = ? WHERE id = ?",
            (totp_result["matchedStep"], user_row["id"]),
        )

    execute_write(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_row["id"],),
    )

    resp = make_response()
    session_meta = issue_session(user_row["id"], resp)

    security_events.publish(
        "auth.login.success",
        {
            "userId": user_row["id"],
            "role": user_row["role"],
            "mfaUsed": bool(user_row["mfa_enabled"]),
            "ip": request.remote_addr,
        },
    )

    resp.set_data(
        jsonify(
            {
                "status": "success",
                "csrfToken": session_meta["csrfToken"],
                "expiresAt": session_meta["expiresAt"],
                "user": {
                    "id": user_row["id"],
                    "fullName": user_row["full_name"],
                    "email": user_row["email"],
                    "role": user_row["role"],
                    "mfaEnabled": bool(user_row["mfa_enabled"]),
                    "permissions": sorted(ROLE_PERMISSIONS.get(user_row["role"], frozenset())),
                },
            }
        ).get_data()
    )
    resp.mimetype = "application/json"
    return resp


@auth_bp.get("/me")
@require_auth
def me() -> Response:
    user = g.user
    return jsonify(
        {
            "status": "success",
            "csrfToken": g.csrf_token,
            "user": {
                **user,
                "permissions": sorted(ROLE_PERMISSIONS.get(user["role"], frozenset())),
            },
        }
    )


@auth_bp.post("/mfa/setup")
@require_auth
def mfa_setup() -> Response:
    secret_b32 = generate_totp_secret()
    encrypted = encrypt_secret(secret_b32)
    # Save strictly into mfa_pending_secret_enc so closing modal never overwrites active MFA
    execute_write(
        "UPDATE users SET mfa_pending_secret_enc = ? WHERE id = ?",
        (encrypted, g.user["id"]),
    )
    qr_info = build_otpauth_qr(g.user["email"], secret_b32)
    return jsonify(
        {
            "status": "success",
            "mfaCurrentlyEnabled": g.user["mfaEnabled"],
            "manualEntryKey": secret_b32,
            "qrDataUrl": qr_info["qrDataUrl"],
        }
    )


@auth_bp.post("/mfa/enable")
@auth_rate_limit
@require_auth
def mfa_enable() -> Response:
    body = parse_json_body(MfaVerifyPayload)
    current_row = query_one("SELECT * FROM users WHERE id = ?", (g.user["id"],))
    if not current_row or not current_row.get("mfa_pending_secret_enc"):
        raise AppError(
            400, "MFA_NOT_INITIALIZED", "Please initialize MFA setup before verifying."
        )

    secret_b32 = decrypt_secret(current_row["mfa_pending_secret_enc"])
    totp_result = verify_totp_code(secret_b32, body.totpCode)
    if not totp_result["valid"]:
        raise AppError(
            400,
            "INVALID_MFA_CODE",
            "The 6-digit code did not match. Ensure your device clock is synced.",
        )

    execute_write(
        """
        UPDATE users
        SET mfa_secret_enc = ?, mfa_pending_secret_enc = NULL, mfa_enabled = 1, mfa_last_used_step = ?
        WHERE id = ?
        """,
        (current_row["mfa_pending_secret_enc"], totp_result["matchedStep"], g.user["id"]),
    )
    security_events.publish("auth.mfa.enabled", {"userId": g.user["id"]})
    return jsonify(
        {
            "status": "success",
            "message": "Two-Factor Authentication (TOTP) is now active on your account.",
        }
    )


@auth_bp.post("/mfa/disable")
@auth_rate_limit
@require_auth
def mfa_disable() -> Response:
    body = parse_json_body(MfaDisablePayload)
    current_row = query_one("SELECT * FROM users WHERE id = ?", (g.user["id"],))
    if not verify_password(
        current_row["password_hash"] if current_row else None, body.password
    ):
        raise AppError(401, "INVALID_CREDENTIALS", "Incorrect password. Unable to disable 2FA.")

    execute_write(
        """
        UPDATE users
        SET mfa_secret_enc = NULL, mfa_pending_secret_enc = NULL, mfa_enabled = 0, mfa_last_used_step = NULL
        WHERE id = ?
        """,
        (g.user["id"],),
    )
    security_events.publish("auth.mfa.disabled", {"userId": g.user["id"]})
    return jsonify(
        {
            "status": "success",
            "message": "Two-Factor Authentication has been disabled on your account.",
        }
    )


@auth_bp.post("/logout")
@require_auth
def logout() -> Response:
    execute_write("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (g.session_token_hash,))
    resp = make_response(
        jsonify({"status": "success", "message": "Signed out securely and session token revoked."})
    )
    clear_session_cookie(resp)
    security_events.publish("auth.logout", {"userId": g.user["id"]})
    return resp

