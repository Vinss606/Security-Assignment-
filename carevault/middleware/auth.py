"""
Requirement 1: Session Authentication & Constant-Time CSRF Verification Middleware
- Uses `__Host-cv_session` Secure, HttpOnly, SameSite=Strict cookies over HTTPS
- Hashes opaque 256-bit session token with HMAC-SHA256 prior to SQLite storage/lookup
- Enforces session-bound CSRF token verification (`hmac.compare_digest`) via `X-CSRF-Token` header
  (for JSON APIs) or `_csrf_token` hidden form field (for pure-Python HTML form submissions)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import Response, g, request

from carevault.config import settings
from carevault.database import execute_write, query_one
from carevault.middleware.error_handler import AppError
from carevault.security.extension_hooks import security_events

SESSION_COOKIE_NAME = "__Host-cv_session"
SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def hash_session_token(raw_token: str) -> str:
    return hmac.new(
        settings.session_hmac_secret,
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def issue_session(user_id: int, response: Response) -> dict[str, str]:
    # Session rotation: revoke any pre-existing session cookie on re-authentication
    existing_raw = request.cookies.get(SESSION_COOKIE_NAME)
    if existing_raw:
        execute_write(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ?",
            (hash_session_token(existing_raw),),
        )

    raw_session_token = secrets.token_hex(32)  # 256-bit CSPRNG token
    csrf_token = secrets.token_hex(24)
    token_hash = hash_session_token(raw_session_token)
    expires_dt = dt.datetime.now(dt.UTC) + dt.timedelta(
        minutes=settings.session_ttl_minutes
    )
    expires_iso = expires_dt.isoformat()

    execute_write(
        """
        INSERT INTO sessions (token_hash, user_id, csrf_token, ip_address, user_agent, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            token_hash,
            user_id,
            csrf_token,
            request.remote_addr or "unknown",
            (request.headers.get("User-Agent") or "unknown")[:250],
            expires_iso,
        ),
    )

    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_session_token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=True,
        samesite="Strict",
        path="/",
    )
    return {"csrfToken": csrf_token, "expiresAt": expires_iso}


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="Strict",
    )


def load_optional_session() -> dict[str, Any] | None:
    """Loads and validates the active session into `flask.g` if present; returns user dict or None."""
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        return None

    token_hash = hash_session_token(raw_token)
    session_row = query_one(
        """
        SELECT s.id AS session_id, s.csrf_token, s.expires_at, s.revoked,
               u.id AS user_id, u.full_name, u.email, u.role, u.assigned_doctor_id,
               u.mfa_enabled, u.locked_until
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ? AND s.revoked = 0
        """,
        (token_hash,),
    )
    if not session_row:
        return None

    now_utc = dt.datetime.now(dt.UTC)
    expires_at = dt.datetime.fromisoformat(session_row["expires_at"])
    if expires_at <= now_utc:
        execute_write("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,))
        return None

    if session_row["locked_until"]:
        locked_dt = dt.datetime.fromisoformat(session_row["locked_until"])
        if locked_dt > now_utc:
            execute_write("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,))
            return None

    user_dict = {
        "id": session_row["user_id"],
        "fullName": session_row["full_name"],
        "email": session_row["email"],
        "role": session_row["role"],
        "assignedDoctorId": session_row["assigned_doctor_id"],
        "mfaEnabled": bool(session_row["mfa_enabled"]),
    }
    g.user = user_dict
    g.session_token_hash = token_hash
    g.csrf_token = session_row["csrf_token"]
    return user_dict


def verify_request_csrf() -> None:
    """Verifies session-bound CSRF token from `X-CSRF-Token` header or `_csrf_token` form field."""
    if request.method in SAFE_HTTP_METHODS:
        return
    expected_csrf = getattr(g, "csrf_token", "")
    supplied_csrf = request.headers.get("X-CSRF-Token") or request.form.get("_csrf_token") or ""
    if not expected_csrf or not supplied_csrf or not hmac.compare_digest(
        expected_csrf.encode("utf-8"), supplied_csrf.encode("utf-8")
    ):
        user = getattr(g, "user", None)
        security_events.publish(
            "csrf.validation.failed",
            {
                "userId": user["id"] if user else None,
                "path": request.path,
                "ip": request.remote_addr,
            },
        )
        raise AppError(
            403,
            "CSRF_TOKEN_INVALID",
            "Security verification token is missing or invalid. Please refresh and try again.",
        )


def require_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        raw_token = request.cookies.get(SESSION_COOKIE_NAME)
        if not raw_token:
            raise AppError(
                401, "AUTHENTICATION_REQUIRED", "Please sign in to access this resource."
            )

        token_hash = hash_session_token(raw_token)
        session_row = query_one(
            """
            SELECT s.id AS session_id, s.csrf_token, s.expires_at, s.revoked,
                   u.id AS user_id, u.full_name, u.email, u.role, u.assigned_doctor_id,
                   u.mfa_enabled, u.locked_until
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.revoked = 0
            """,
            (token_hash,),
        )
        if not session_row:
            raise AppError(
                401, "SESSION_INVALID", "Your session is invalid or has been signed out."
            )

        now_utc = dt.datetime.now(dt.UTC)
        expires_at = dt.datetime.fromisoformat(session_row["expires_at"])
        if expires_at <= now_utc:
            execute_write("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,))
            raise AppError(
                401,
                "SESSION_EXPIRED",
                "Your session has expired for security. Please sign in again.",
            )

        if session_row["locked_until"]:
            locked_dt = dt.datetime.fromisoformat(session_row["locked_until"])
            if locked_dt > now_utc:
                execute_write(
                    "UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,)
                )
                raise AppError(403, "ACCOUNT_LOCKED", "Your account is temporarily locked.")

        g.user = {
            "id": session_row["user_id"],
            "fullName": session_row["full_name"],
            "email": session_row["email"],
            "role": session_row["role"],
            "assignedDoctorId": session_row["assigned_doctor_id"],
            "mfaEnabled": bool(session_row["mfa_enabled"]),
        }
        g.session_token_hash = token_hash
        g.csrf_token = session_row["csrf_token"]

        verify_request_csrf()
        return fn(*args, **kwargs)

    return wrapper
