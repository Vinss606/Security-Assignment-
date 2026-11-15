"""
Requirement 1 & CLO1: Thread-Safe Sliding-Window Endpoint & Network Rate Limiter
Protects authentication endpoints against automated credential stuffing / Argon2id floods
and protects API and Portal routes against scraping and Denial-of-Service bursts.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import jsonify, make_response, render_template, request


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int, code: str, message: str) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.code = code
        self.message = message
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check_or_reject(self, client_key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits[client_key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_auth_limiter = SlidingWindowRateLimiter(
    max_requests=40,
    window_seconds=15 * 60,
    code="RATE_LIMIT_EXCEEDED",
    message="Too many authentication attempts from this network address. Please wait 15 minutes.",
)

_api_limiter = SlidingWindowRateLimiter(
    max_requests=180,
    window_seconds=60,
    code="API_RATE_LIMIT_EXCEEDED",
    message="Request rate limit exceeded. Please slow down your requests.",
)


def _rate_limit_response(limiter: SlidingWindowRateLimiter) -> Any:
    correlation_id = f"ERR-{secrets.token_hex(4).upper()}"
    if not request.path.startswith("/api/"):
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "text/html":
            html = render_template(
                "error.html",
                status_code=429,
                error_code=limiter.code,
                message=limiter.message,
                correlation_id=correlation_id,
            )
            resp = make_response(html, 429)
            resp.mimetype = "text/html"
            return resp
    return (
        jsonify(
            {
                "status": "error",
                "code": limiter.code,
                "message": limiter.message,
                "correlationId": correlation_id,
            }
        ),
        429,
    )


def auth_rate_limit(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        ip = request.remote_addr or "unknown"
        if not _auth_limiter.check_or_reject(ip):
            return _rate_limit_response(_auth_limiter)
        return fn(*args, **kwargs)

    return wrapper


def enforce_api_rate_limit() -> Any:
    if request.path.startswith("/static/"):
        return None
    ip = request.remote_addr or "unknown"
    if not _api_limiter.check_or_reject(ip):
        return _rate_limit_response(_api_limiter)
    return None


def reset_all_rate_limits() -> None:
    _auth_limiter.reset()
    _api_limiter.reset()
