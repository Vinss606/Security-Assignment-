"""
Requirement 2: Centralized Safe Error Handling & Sensitive Credential Redaction
- Prevents Python traceback, SQLite schema, file path, and WSGI banner leakage (OWASP A05:2021)
- Generates a unique Correlation ID (`ERR-XXXXXXXX`) for safe user-facing support reference
- Recursively scrubs passwords, tokens, cookies, and MFA secrets to `[REDACTED]` before disk logging
- Content-negotiates JSON for `/api/*` clients and styled HTML (`error.html`) for browser navigations
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import sys
import traceback
from datetime import UTC, datetime
from typing import Any

from flask import Flask, Response, g, jsonify, make_response, render_template, request
from werkzeug.exceptions import BadRequest, HTTPException, RequestEntityTooLarge

from carevault.config import settings
from carevault.security.extension_hooks import security_events

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwordhash",
        "password_hash",
        "token",
        "csrftoken",
        "csrf_token",
        "_csrf_token",
        "totpcode",
        "mfa_secret_enc",
        "mfa_pending_secret_enc",
        "mfachallengetoken",
        "mfa_challenge_token",
        "secret",
        "cookie",
        "authorization",
    }
)

_SENSITIVE_SUBSTRINGS = ("password", "secret", "token", "cookie", "totp")


class AppError(Exception):
    def __init__(
        self,
        status_code: int,
        error_code: str,
        public_message: str,
        details: list[dict[str, str]] | None = None,
    ) -> None:
        super().__init__(public_message)
        self.status_code = status_code
        self.error_code = error_code
        self.public_message = public_message
        self.details = details


def _is_sensitive_key(key_name: str) -> bool:
    lowered = key_name.lower()
    if lowered in SENSITIVE_KEYS:
        return True
    return any(sub in lowered for sub in _SENSITIVE_SUBSTRINGS)


def redact_sensitive_object(obj: Any, depth: int = 0) -> Any:
    if depth > 4 or obj is None:
        return obj
    if isinstance(obj, list):
        return [redact_sensitive_object(item, depth + 1) for item in obj]
    if isinstance(obj, dict):
        sanitized: dict[str, Any] = {}
        for k, v in obj.items():
            key_str = str(k)
            if _is_sensitive_key(key_str):
                sanitized[key_str] = "[REDACTED]"
            else:
                sanitized[key_str] = redact_sensitive_object(v, depth + 1)
        return sanitized
    return obj


def _extract_sanitized_request_body() -> Any:
    json_body = request.get_json(silent=True)
    if json_body is not None:
        return redact_sensitive_object(json_body)
    if request.form:
        return redact_sensitive_object(request.form.to_dict(flat=True))
    return None


def _wants_html_response() -> bool:
    if request.path.startswith("/api/"):
        return False
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "text/html"


def _format_error_response(
    status_code: int,
    error_code: str,
    message: str,
    correlation_id: str,
    details: list[dict[str, str]] | None = None,
) -> tuple[Response, int]:
    if _wants_html_response():
        html = render_template(
            "error.html",
            status_code=status_code,
            error_code=error_code,
            message=message,
            correlation_id=correlation_id,
        )
        resp = make_response(html, status_code)
        resp.mimetype = "text/html"
        return resp, status_code

    payload: dict[str, Any] = {
        "status": "error",
        "code": error_code,
        "message": message,
        "correlationId": correlation_id,
    }
    if details:
        payload["details"] = details
    return jsonify(payload), status_code


def _write_internal_error_log(entry: dict[str, Any]) -> None:
    try:
        settings.error_log_path.parent.mkdir(parents=True, exist_ok=True)
        with settings.error_log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        with contextlib.suppress(OSError):
            os.chmod(settings.error_log_path, 0o600)
    except (OSError, TypeError, ValueError) as exc:
        sys.stderr.write(f"[ERROR_LOG] Failed to write internal error log: {exc}\n")


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(RequestEntityTooLarge)
    def handle_payload_too_large(_err: RequestEntityTooLarge) -> tuple[Response, int]:
        correlation_id = f"ERR-{secrets.token_hex(4).upper()}"
        return _format_error_response(
            413,
            "PAYLOAD_TOO_LARGE",
            "Request body exceeds the 16 KB security limit.",
            correlation_id,
        )

    @app.errorhandler(BadRequest)
    def handle_bad_request(err: BadRequest) -> tuple[Response, int]:
        correlation_id = f"ERR-{secrets.token_hex(4).upper()}"
        _write_internal_error_log(
            {
                "correlationId": correlation_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "statusCode": 400,
                "errorCode": "MALFORMED_JSON",
                "method": request.method,
                "path": request.path,
                "ip": request.remote_addr,
                "internalMessage": str(err.description),
            }
        )
        return _format_error_response(
            400,
            "MALFORMED_JSON",
            "The request payload is not valid JSON. Please check your input format.",
            correlation_id,
        )

    @app.errorhandler(AppError)
    def handle_app_error(err: AppError) -> tuple[Response, int]:
        correlation_id = f"ERR-{secrets.token_hex(4).upper()}"
        current_user = getattr(g, "user", None)

        internal_record = {
            "correlationId": correlation_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "statusCode": err.status_code,
            "errorCode": err.error_code,
            "method": request.method,
            "path": request.path,
            "userId": current_user["id"] if current_user else None,
            "ip": request.remote_addr,
            "sanitizedBody": _extract_sanitized_request_body(),
            "internalMessage": err.public_message,
        }
        _write_internal_error_log(internal_record)
        security_events.publish(
            "error.handled",
            {
                "correlationId": correlation_id,
                "statusCode": err.status_code,
                "errorCode": err.error_code,
                "path": request.path,
                "userId": current_user["id"] if current_user else None,
            },
        )
        return _format_error_response(
            err.status_code,
            err.error_code,
            err.public_message,
            correlation_id,
            err.details,
        )

    @app.errorhandler(HTTPException)
    def handle_http_exception(err: HTTPException) -> tuple[Response, int]:
        correlation_id = f"ERR-{secrets.token_hex(4).upper()}"
        status = err.code or 404
        http_map: dict[int, tuple[str, str]] = {
            404: (
                "RESOURCE_NOT_FOUND",
                "The requested endpoint or clinical resource could not be found.",
            ),
            405: (
                "METHOD_NOT_ALLOWED",
                "HTTP method is not permitted on this endpoint.",
            ),
            415: (
                "UNSUPPORTED_MEDIA_TYPE",
                "Unsupported Content-Type supplied in request.",
            ),
        }
        code, msg = http_map.get(status, ("HTTP_REQUEST_ERROR", "Unable to process HTTP request."))
        return _format_error_response(status, code, msg, correlation_id)

    @app.errorhandler(Exception)
    def handle_unexpected_exception(err: Exception) -> tuple[Response, int]:
        correlation_id = f"ERR-{secrets.token_hex(4).upper()}"
        current_user = getattr(g, "user", None)

        _write_internal_error_log(
            {
                "correlationId": correlation_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "statusCode": 500,
                "errorCode": "INTERNAL_SYSTEM_ERROR",
                "method": request.method,
                "path": request.path,
                "userId": current_user["id"] if current_user else None,
                "ip": request.remote_addr,
                "sanitizedBody": _extract_sanitized_request_body(),
                "internalErrorName": type(err).__name__,
                "internalMessage": str(err),
                "traceback": traceback.format_exc(),
            }
        )
        return _format_error_response(
            500,
            "INTERNAL_SYSTEM_ERROR",
            (
                "An unexpected error occurred while processing your request. "
                f"Please try again or contact support quoting reference {correlation_id}."
            ),
            correlation_id,
        )
