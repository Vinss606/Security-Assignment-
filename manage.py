"""
CareVault Management CLI (`python manage.py [certs|seed|reset-db|setup]`)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

_APP_ROOT = Path(__file__).resolve().parent
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from carevault.security.pki_generator import generate_pki
from carevault.security.tls_validator import validate_certificate_chain
from carevault.seed import seed_database


def main() -> int:
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "setup"

    if cmd == "certs":
        generate_pki()
        summary = validate_certificate_chain()
        print(f"[PKI] Verified {len(summary['checks'])}/6 cryptographic X.509 checks.")
        return 0

    if cmd == "seed":
        seed_database(force_reset=False)
        return 0

    if cmd == "reset-db":
        seed_database(force_reset=True)
        return 0

    if cmd == "setup":
        generate_pki()
        summary = validate_certificate_chain()
        print(f"[PKI] Verified {len(summary['checks'])}/6 cryptographic X.509 checks.")
        seed_database(force_reset=False)
        print("[SETUP] CareVault Python environment is ready. Run `python run.py` to start.")
        return 0

    print("Usage: python manage.py [certs|seed|reset-db|setup]")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
