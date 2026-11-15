"""
CareVault Flask Application Factory (`carevault/__init__.py`)
100% Pure-Python Clinical Portal (Server-Side Jinja2 UI + REST JSON APIs)
"""
from __future__ import annotations

import ssl
import sys
from pathlib import Path

sys.dont_write_bytecode = True

# Allow running `python carevault/__init__.py` directly from IDE "Run Python File" button
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from flask import Flask, Response, jsonify, request

from carevault.config import settings
from carevault.middleware.error_handler import register_error_handlers
from carevault.middleware.rate_limiter import enforce_api_rate_limit
from carevault.middleware.security_headers import register_security_headers
from carevault.routes.admin_routes import admin_bp
from carevault.routes.appointment_routes import appointments_bp
from carevault.routes.auth_routes import auth_bp
from carevault.routes.portal_routes import portal_bp
from carevault.routes.record_routes import records_bp


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(settings.ROOT_DIR / "templates"),
        static_folder=str(settings.ROOT_DIR / "static"),
        static_url_path="/static",
    )

    # Strict 16 KB request body limit to prevent payload memory-exhaustion DoS
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    register_security_headers(app)
    register_error_handlers(app)
    app.before_request(enforce_api_rate_limit)

    app.register_blueprint(portal_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(records_bp)
    app.register_blueprint(appointments_bp)
    app.register_blueprint(admin_bp)

    @app.get("/api/health")
    def health_probe() -> Response:
        raw_sock = request.environ.get("werkzeug.socket")
        is_tls = isinstance(raw_sock, ssl.SSLSocket) or request.is_secure
        return jsonify({"status": "ok", "tls": is_tls})

    return app


if __name__ == "__main__":
    from carevault.server import start_servers

    start_servers()
