"""
Requirement 3: X.509 Certificate Chain Validator & Hardened TLS 1.2/1.3 `ssl.SSLContext`
- Verifies 6 cryptographic X.509 invariants using `cryptography.x509` before opening sockets
- Enforces TLS 1.2 / TLS 1.3 ONLY with Forward-Secrecy AEAD cipher suites (NIST SP 800-52r2)
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from carevault.config import settings

# NIST SP 800-52 Rev. 2 Forward-Secrecy AEAD Cipher Policy (TLS 1.3 suites are auto-enabled by OpenSSL)
HARDENED_TLS12_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256"
)


def _fingerprint_sha256(cert: x509.Certificate) -> str:
    raw = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in raw)


def validate_certificate_chain(
    ca_cert_path: Path | None = None,
    server_cert_path: Path | None = None,
    server_key_path: Path | None = None,
    expected_hostname: str = "localhost",
) -> dict[str, Any]:
    ca_path = ca_cert_path or settings.tls_ca_cert_path
    srv_path = server_cert_path or settings.tls_server_cert_path
    key_path = server_key_path or settings.tls_server_key_path

    if not (ca_path.exists() and srv_path.exists() and key_path.exists()):
        raise RuntimeError(
            "TLS certificate or key files missing. Run `python manage.py setup` first."
        )

    ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    srv_cert = x509.load_pem_x509_certificate(srv_path.read_bytes())
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    checks: list[dict[str, Any]] = []

    # 1. Root CA BasicConstraints check
    try:
        ca_bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_root_ca = ca_bc.ca is True
    except x509.ExtensionNotFound:
        is_root_ca = False
    checks.append({"check": "Root Certificate CA BasicConstraint", "passed": is_root_ca})

    # 2. Cryptographic signature verification against Root CA public key
    try:
        srv_cert.verify_directly_issued_by(ca_cert)
        sig_valid = True
    except (ValueError, TypeError, InvalidSignature):
        sig_valid = False
    checks.append({"check": "Server Certificate Signed by Trusted Root CA", "passed": sig_valid})

    # 3. Server Private Key matches X.509 Certificate Public Key
    srv_pub = srv_cert.public_key()
    priv_pub = private_key.public_key()
    key_matches = srv_pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == priv_pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    checks.append({"check": "Server Private Key Matches X.509 Public Key", "passed": key_matches})

    # 4. Temporal validity window check
    now = dt.datetime.now(dt.UTC)
    valid_from = srv_cert.not_valid_before_utc
    valid_to = srv_cert.not_valid_after_utc
    days_remaining = (valid_to - now).days
    within_window = valid_from <= now <= valid_to and days_remaining > 0
    checks.append(
        {
            "check": "Certificate Within Validity Period",
            "passed": within_window,
            "daysRemaining": days_remaining,
        }
    )

    # 5. Subject Alternative Name (SAN) Hostname & Loopback IP check
    try:
        san = srv_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addrs = san.get_values_for_type(x509.IPAddress)
        san_ok = (expected_hostname in dns_names) and (
            ipaddress.ip_address("127.0.0.1") in ip_addrs
        )
        san_str = ", ".join(
            [f"DNS:{d}" for d in dns_names] + [f"IP Address:{ip}" for ip in ip_addrs]
        )
    except x509.ExtensionNotFound:
        san_ok = False
        san_str = ""
    checks.append(
        {
            "check": f"SAN Matches Host ({expected_hostname}) & Loopback IP",
            "passed": san_ok,
        }
    )

    # 6. Asymmetric key size >= 2048-bit RSA
    modulus_len = srv_pub.key_size if isinstance(srv_pub, rsa.RSAPublicKey) else 0
    checks.append(
        {
            "check": "Asymmetric Key Strength >= 2048-bit RSA",
            "passed": modulus_len >= 2048,
            "modulusLength": modulus_len,
        }
    )

    failed = [c["check"] for c in checks if not c["passed"]]
    if failed:
        raise RuntimeError(f"TLS Certificate Chain Validation Failed: {', '.join(failed)}")

    return {
        "valid": True,
        "protocolPolicy": {
            "minVersion": "TLSv1.2",
            "maxVersion": "TLSv1.3",
            "ciphers": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256",
                *HARDENED_TLS12_CIPHERS.split(":"),
            ],
        },
        "rootCA": {
            "subject": ca_cert.subject.rfc4514_string(),
            "fingerprint256": _fingerprint_sha256(ca_cert),
            "validTo": ca_cert.not_valid_after_utc.isoformat(),
        },
        "serverCert": {
            "subject": srv_cert.subject.rfc4514_string(),
            "issuer": srv_cert.issuer.rfc4514_string(),
            "subjectAltName": san_str,
            "serialNumber": hex(srv_cert.serial_number),
            "fingerprint256": _fingerprint_sha256(srv_cert),
            "validFrom": valid_from.isoformat(),
            "validTo": valid_to.isoformat(),
            "daysRemaining": days_remaining,
            "modulusLength": modulus_len,
        },
        "checks": checks,
    }


def build_ssl_context() -> tuple[ssl.SSLContext, dict[str, Any]]:
    summary = validate_certificate_chain()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers(HARDENED_TLS12_CIPHERS)
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.load_cert_chain(
        certfile=str(settings.tls_server_cert_path),
        keyfile=str(settings.tls_server_key_path),
    )
    ctx.load_verify_locations(cafile=str(settings.tls_ca_cert_path))
    return ctx, summary

