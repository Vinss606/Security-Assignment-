"""
Requirement 1 (Enhanced Authentication): RFC 6238 TOTP Multi-Factor Authentication
- Generates 160-bit CSPRNG Base32 secrets compatible with Google/Microsoft Authenticator
- Encrypts TOTP secrets at rest using AES-256-GCM authenticated encryption (`AESGCM`)
- Performs constant-time OTP comparison (`hmac.compare_digest`) + RFC 6238 replay blocking
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import struct
import time
from typing import Any
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from carevault.config import settings
from carevault.security.qr_generator import build_qr_png_data_url


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _decode_base32(secret_b32: str) -> bytes:
    cleaned = re.sub(r"[^A-Z2-7]", "", secret_b32.upper())
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)


def compute_hotp(secret_b32: str, counter: int) -> str:
    key = _decode_base32(secret_b32)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code_int % 1_000_000:06d}"


def generate_current_totp(secret_b32: str, timestamp_sec: float | None = None) -> str:
    ts = time.time() if timestamp_sec is None else timestamp_sec
    return compute_hotp(secret_b32, int(ts // 30))


def verify_totp_code(
    secret_b32: str,
    user_token: str | None,
    *,
    timestamp_sec: float | None = None,
    last_used_step: int | None = None,
) -> dict[str, Any]:
    token_str = re.sub(r"[\s-]+", "", user_token or "")
    if not re.fullmatch(r"\d{6}", token_str):
        return {"valid": False, "matchedStep": None, "replayed": False}

    ts = time.time() if timestamp_sec is None else timestamp_sec
    current_step = int(ts // 30)

    for drift in (-1, 0, 1):
        candidate_step = current_step + drift
        expected = compute_hotp(secret_b32, candidate_step)
        if hmac.compare_digest(expected.encode("ascii"), token_str.encode("ascii")):
            if last_used_step is not None and candidate_step <= last_used_step:
                return {"valid": False, "matchedStep": candidate_step, "replayed": True}
            return {"valid": True, "matchedStep": candidate_step, "replayed": False}

    return {"valid": False, "matchedStep": None, "replayed": False}


def encrypt_secret(plain_secret: str) -> str:
    nonce = os.urandom(12)  # 96-bit NIST-recommended GCM IV
    aesgcm = AESGCM(settings.mfa_encryption_key)
    ct_with_tag = aesgcm.encrypt(nonce, plain_secret.encode("utf-8"), None)
    return f"{nonce.hex()}:{ct_with_tag.hex()}"


def decrypt_secret(encrypted_payload: str) -> str:
    nonce_hex, ct_hex = encrypted_payload.split(":", 1)
    aesgcm = AESGCM(settings.mfa_encryption_key)
    plaintext = aesgcm.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)
    return plaintext.decode("utf-8")


def build_otpauth_qr(email: str, secret_b32: str) -> dict[str, str]:
    issuer = "CareVaultPortal"
    otpauth_url = (
        f"otpauth://totp/{quote(issuer)}:{quote(email)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )
    return {
        "otpauthUrl": otpauth_url,
        "qrDataUrl": build_qr_png_data_url(otpauth_url),
    }

