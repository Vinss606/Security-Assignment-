"""
Insecure Configuration for CareVault Baseline (carevault/config.py)
INTENTIONALLY VULNERABLE BASELINE:
- Hardcoded secrets and debug mode enabled
- Plaintext HTTP on port 5000
- No security headers, no CSP, no rate limiting
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "carevault.db"

HTTP_HOST = "0.0.0.0"
HTTP_PORT = 5000
DEBUG_MODE = True
SECRET_KEY = "insecure-hardcoded-secret-key-12345"

