"""
Requirement 1: Memory-Hard Password Hashing (Argon2id) & NIST SP 800-63B Policy
- Uses OpenSSL/cryptography C-accelerated Argon2id (64 MiB memory, 3 iterations, 4 lanes)
- Enforces NIST SP 800-63B length, diversity, breached-list, and contextual identifier checks
- Executes constant-time dummy Argon2id verification when email is unknown (anti-enumeration)
"""
from __future__ import annotations

import math
import os
import re
from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

ARGON2_MEMORY_KIB = 65536  # 64 MiB (OWASP Password Storage Cheat Sheet)
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_HASH_LEN = 32

BREACHED_PASSWORDS = frozenset(
    {
        "password123!",
        "welcome12345",
        "qwertyuiop12",
        "admin1234567",
        "carevault123",
        "letmein12345",
        "iloveyou1234",
        "hospital1234",
        "doctor123456",
    }
)


def hash_password(plain_password: str) -> str:
    kdf = Argon2id(
        salt=os.urandom(16),
        length=ARGON2_HASH_LEN,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    )
    return kdf.derive_phc_encoded(plain_password.encode("utf-8"))


# Precomputed dummy hash on module load so unknown-email logins run identical Argon2id work
_DUMMY_PHC_HASH = hash_password("DummyAntiEnumerationPassword!2026#")


def verify_password(stored_phc_hash: str | None, candidate_password: str) -> bool:
    target_hash = stored_phc_hash if stored_phc_hash else _DUMMY_PHC_HASH
    try:
        Argon2id.verify_phc_encoded(candidate_password.encode("utf-8"), target_hash)
        return bool(stored_phc_hash)
    except InvalidKey:
        return False


def calculate_entropy_bits(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0
    return round(len(password) * math.log2(pool))


def validate_password_policy(
    password: str, context_identifiers: list[str] | None = None
) -> dict[str, Any]:
    issues: list[str] = []
    if not isinstance(password, str):
        return {"valid": False, "issues": ["Password must be a string."], "entropyBits": 0}

    if len(password) < 12:
        issues.append("Password must be at least 12 characters long (NIST SP 800-63B).")
    if len(password) > 128:
        issues.append("Password must not exceed 128 characters.")
    if not re.search(r"[a-z]", password):
        issues.append("Must include at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        issues.append("Must include at least one uppercase letter.")
    if not re.search(r"[0-9]", password):
        issues.append("Must include at least one digit.")
    if not re.search(r"[^a-zA-Z0-9\s]", password):
        issues.append("Must include at least one special character.")

    lower_pwd = password.lower()
    if lower_pwd in BREACHED_PASSWORDS:
        issues.append("Password appears in known breached credential lists.")
    if re.search(r"(.)\1{3,}", password):
        issues.append("Password cannot contain 4 or more identical consecutive characters.")

    found_context_match = False
    for ident in context_identifiers or []:
        if not ident or len(ident) < 3:
            continue
        email_prefix = ident.lower().split("@")[0].strip()
        tokens = [email_prefix, *re.split(r"[^a-z0-9]+", email_prefix)]
        for tok in tokens:
            if len(tok) >= 3 and tok in lower_pwd:
                issues.append("Password must not contain your username, name, or email identifier.")
                found_context_match = True
                break
        if found_context_match:
            break

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "entropyBits": calculate_entropy_bits(password),
    }
