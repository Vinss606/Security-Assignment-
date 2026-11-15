"""
Requirement 3: Pure-Python Two-Tier X.509v3 PKI Generator (`cryptography.x509`)
Generates:
  1) CareVault Local Root CA (4096-bit RSA, SHA-256, BasicConstraints CA:TRUE, pathlen:0)
  2) CareVault Server TLS Certificate signed by Root CA with X.509v3 SANs
     (`DNS:localhost`, `DNS:carevault.local`, `IP:127.0.0.1`) and `ExtendedKeyUsage(SERVER_AUTH)`
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from carevault.config import settings


def generate_pki() -> dict[str, str]:
    settings.CERTS_DIR.mkdir(parents=True, exist_ok=True)
    ca_key_path = settings.CERTS_DIR / "carevault-root-ca.key"
    ca_cert_path = settings.tls_ca_cert_path
    server_key_path = settings.tls_server_key_path
    server_cert_path = settings.tls_server_cert_path

    now = dt.datetime.now(dt.UTC)

    # 1. Generate 4096-bit RSA Root CA Key & Self-Signed Root Certificate
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MY"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Selangor"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Subang Jaya"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CareVault Healthcare Security Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI Trust Infrastructure"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CareVault Local Root CA"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    # 2. Generate 2048-bit RSA Leaf Server Key & Root-Signed X.509v3 SAN Certificate
    server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MY"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Selangor"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Subang Jaya"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CareVault Clinical Portal"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Application Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    san_extension = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.DNSName("carevault.local"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]
    )

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(san_extension, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    ca_key_path.write_bytes(
        ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    server_key_path.write_bytes(
        server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    for key_file in (ca_key_path, server_key_path):
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass

    # Verify cryptographic signature before returning
    server_cert.verify_directly_issued_by(ca_cert)
    print("[PKI] SUCCESS: 4096-bit Root CA and 2048-bit SAN Server TLS Certificates generated & verified.")
    return {
        "caCert": str(ca_cert_path),
        "serverCert": str(server_cert_path),
        "serverKey": str(server_key_path),
    }

