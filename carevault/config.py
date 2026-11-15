"""
CareVault Configuration & Secret Loader (carevault/config.py)
- Auto-provisions a local `.env` with 256-bit CSPRNG cryptographic keys if missing
- Supports runtime overrides (e.g. `DB_PATH` & `ERROR_LOG_PATH`) for isolated security testing
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT_DIR / ".env"


def _ensure_and_load_dotenv() -> None:
    if not ENV_FILE.exists():
        generated = "\n".join(
            [
                "APP_ENV=development",
                "HTTPS_PORT=8443",
                "HTTP_REDIRECT_PORT=8080",
                f"SESSION_HMAC_SECRET={secrets.token_hex(32)}",
                f"MFA_ENCRYPTION_KEY={secrets.token_hex(32)}",
                "MAX_FAILED_LOGIN_ATTEMPTS=5",
                "ACCOUNT_LOCKOUT_MINUTES=15",
                "SESSION_TTL_MINUTES=30",
                "TLS_CA_CERT_PATH=./certs/carevault-root-ca.crt",
                "TLS_SERVER_CERT_PATH=./certs/carevault-server.crt",
                "TLS_SERVER_KEY_PATH=./certs/carevault-server.key",
                "",
            ]
        )
        ENV_FILE.write_text(generated, encoding="utf-8")
        try:
            os.chmod(ENV_FILE, 0o600)
        except OSError:
            pass

    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip())


_ensure_and_load_dotenv()


class Settings:
    ROOT_DIR: Path = ROOT_DIR
    DATA_DIR: Path = ROOT_DIR / "data"
    CERTS_DIR: Path = ROOT_DIR / "certs"

    @property
    def https_port(self) -> int:
        return int(os.environ.get("HTTPS_PORT", "8443"))

    @property
    def http_redirect_port(self) -> int:
        return int(os.environ.get("HTTP_REDIRECT_PORT", "8080"))

    @property
    def session_hmac_secret(self) -> bytes:
        return os.environ["SESSION_HMAC_SECRET"].encode("utf-8")

    @property
    def mfa_encryption_key(self) -> bytes:
        return bytes.fromhex(os.environ["MFA_ENCRYPTION_KEY"])

    @property
    def max_failed_login_attempts(self) -> int:
        return int(os.environ.get("MAX_FAILED_LOGIN_ATTEMPTS", "5"))

    @property
    def account_lockout_minutes(self) -> int:
        return int(os.environ.get("ACCOUNT_LOCKOUT_MINUTES", "15"))

    @property
    def session_ttl_minutes(self) -> int:
        return int(os.environ.get("SESSION_TTL_MINUTES", "30"))

    @property
    def tls_ca_cert_path(self) -> Path:
        return (ROOT_DIR / os.environ.get("TLS_CA_CERT_PATH", "./certs/carevault-root-ca.crt")).resolve()

    @property
    def tls_server_cert_path(self) -> Path:
        return (ROOT_DIR / os.environ.get("TLS_SERVER_CERT_PATH", "./certs/carevault-server.crt")).resolve()

    @property
    def tls_server_key_path(self) -> Path:
        return (ROOT_DIR / os.environ.get("TLS_SERVER_KEY_PATH", "./certs/carevault-server.key")).resolve()

    @property
    def db_path(self) -> Path:
        override = os.environ.get("DB_PATH")
        if override:
            return (ROOT_DIR / override).resolve()
        return self.DATA_DIR / "carevault.db"

    @property
    def error_log_path(self) -> Path:
        override = os.environ.get("ERROR_LOG_PATH")
        if override:
            return (ROOT_DIR / override).resolve()
        return self.DATA_DIR / "internal-errors.jsonl"


settings = Settings()

