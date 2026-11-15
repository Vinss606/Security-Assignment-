"""
CareVault Insecure Application Factory (carevault/__init__.py)
INTENTIONALLY VULNERABLE BASELINE:
- Runs in DEBUG mode with interactive Werkzeug debugger enabled (CWE-209)
- Omits all security headers: No CSP, No HSTS, No XFO, No nosniff (CWE-693)
- Omits API rate limiting (CWE-770)
- Omits request body size limits (CWE-400)
"""
from __future__ import annotations

import sys
from pathlib import Path
from flask import Flask, jsonify, request, render_template

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from carevault.config import ROOT_DIR, SECRET_KEY, DEBUG_MODE
from carevault.database import init_db
from carevault.seed import seed_database
from carevault.routes.auth_routes import auth_bp
from carevault.routes.record_routes import records_bp
from carevault.routes.appointment_routes import appointments_bp
from carevault.routes.admin_routes import admin_bp
from carevault.routes.portal_routes import portal_bp


def create_insecure_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(ROOT_DIR / "templates"),
        static_folder=str(ROOT_DIR / "static"),
        static_url_path="/static",
    )

    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DEBUG"] = DEBUG_MODE

    # VULNERABILITY: No MAX_CONTENT_LENGTH - allows unbounded payload memory exhaustion
    # VULNERABILITY: No security headers registered - no CSP, no HSTS, no X-Frame-Options
    # VULNERABILITY: No rate limiter middleware registered

    init_db()
    seed_database(force_reset=False)

    app.register_blueprint(portal_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(records_bp)
    app.register_blueprint(appointments_bp)
    app.register_blueprint(admin_bp)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "mode": "insecure_baseline", "tls": False, "port": 5000})

    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not Found", "status_code": 404}), 404
        return render_template(
            "error.html",
            status_code=404,
            error_title="Page Not Found",
            message=f"The requested path '{request.path}' was not found on this server.",
        ), 404

    @app.errorhandler(405)
    def handle_405(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Method Not Allowed", "status_code": 405}), 405
        return render_template(
            "error.html",
            status_code=405,
            error_title="Method Not Allowed",
            message=f"The HTTP method '{request.method}' is not allowed for '{request.path}'.",
        ), 405

    return app

