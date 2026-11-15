"""
CareVault Production-Style HTTPS Entrypoint (`python run.py`)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

_APP_ROOT = Path(__file__).resolve().parent
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from carevault.server import start_servers

if __name__ == "__main__":
    start_servers()
