"""
CareVault Insecure Server Entrypoint (`python run.py`)
Binds plain HTTP on port 5000 without TLS/HTTPS
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

_APP_ROOT = Path(__file__).resolve().parent
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from carevault import create_insecure_app
from carevault.config import HTTP_HOST, HTTP_PORT, DEBUG_MODE

if __name__ == "__main__":
    print("=" * 70)
    print("  CareVault VULNERABLE BASELINE Portal (Plaintext HTTP Edition)")
    print(f"  Plaintext Portal : http://127.0.0.1:{HTTP_PORT}")
    print(f"  Localhost URL    : http://localhost:{HTTP_PORT}")
    print("  Security Status  : UNSECURED BASELINE (SQLi, IDOR, XSS, No TLS, No CSRF)")
    print("=" * 70)
    app = create_insecure_app()
    app.run(host=HTTP_HOST, port=HTTP_PORT, debug=DEBUG_MODE, use_reloader=False)

