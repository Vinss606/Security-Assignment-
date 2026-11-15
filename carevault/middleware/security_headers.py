"""
Requirement 2, 3 & CLO1: HTTP Security Headers & Strict Content Security Policy (CSP)
- Blocks all browser scripts (`script-src 'none'`, zero JS) against XSS
- Enforces 2-year HSTS + preload against SSL-stripping / protocol downgrade attacks
- Denies framing (`frame-ancestors 'none'`, `X-Frame-Options: DENY`) against Clickjacking
- Disables browser caching (`Cache-Control: no-store`) on PHI responses and strips `Server` banners
"""
from __future__ import annotations

from flask import Flask, Response, request

CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'none'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests"
)


def register_security_headers(app: Flask) -> None:
    @app.after_request
    def apply_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = CSP_POLICY
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers.pop("X-Powered-By", None)
        response.headers.pop("Server", None)

        if not request.path.startswith("/static/") and request.path != "/favicon.ico":
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response

