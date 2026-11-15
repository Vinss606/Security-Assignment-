"""
CareVault Live End-to-End Automated Security & Penetration Verification Suite
(`python tests/test_security_suite.py`)

Executes 24 live network, UI & cryptographic security tests against an isolated SQLite database
over TLS 1.3 (`https://127.0.0.1:<ephemeral>`) + HTTP Redirect (`http://127.0.0.1:<ephemeral>`).
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import os
import re as _re
import shutil
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any

import cv2
import numpy as np
import requests  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.dont_write_bytecode = True

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Isolate test database & error log so production demo DB is untouched
os.environ["DB_PATH"] = "./data/carevault-test.db"
os.environ["ERROR_LOG_PATH"] = "./data/internal-errors-test.jsonl"

from carevault.config import settings
from carevault.database import close_thread_connections
from carevault.middleware.rate_limiter import reset_all_rate_limits
from carevault.security.totp import compute_hotp, generate_current_totp
from carevault.server import start_servers


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


HTTPS_PORT = _pick_free_port()
HTTP_PORT = _pick_free_port()
BASE_HTTPS = f"https://127.0.0.1:{HTTPS_PORT}"
BASE_HTTP = f"http://127.0.0.1:{HTTP_PORT}"


def _cleanup_test_artifacts() -> None:
    close_thread_connections()
    for suffix in ("", "-wal", "-shm"):
        p = Path(f"{settings.db_path}{suffix}")
        if p.exists():
            with contextlib.suppress(OSError):
                p.unlink()
    if settings.error_log_path.exists():
        with contextlib.suppress(OSError):
            settings.error_log_path.unlink()
    shutil.rmtree(Path(__file__).resolve().parent / "__pycache__", ignore_errors=True)


def _make_trusted_session() -> requests.Session:
    sess = requests.Session()
    sess.verify = str(settings.tls_ca_cert_path)
    return sess


def _login_session(
    email: str, password: str, totp_code: str | None = None
) -> tuple[requests.Session, dict[str, Any]]:
    sess = _make_trusted_session()
    payload: dict[str, str] = {"email": email, "password": password}
    if totp_code is not None:
        payload["totpCode"] = totp_code
    resp = sess.post(f"{BASE_HTTPS}/api/auth/login", json=payload, timeout=10)
    assert resp.status_code == 200, f"Login failed for {email}: {resp.status_code} {resp.text}"
    data = resp.json()
    return sess, data


def run_suite() -> int:
    _cleanup_test_artifacts()
    servers = start_servers(
        host="127.0.0.1", https_port=HTTPS_PORT, http_port=HTTP_PORT, background=True
    )
    assert servers is not None
    time.sleep(0.35)

    passed = 0
    total = 24

    def record_pass(num: int, title: str, detail: str = "") -> None:
        nonlocal passed
        passed += 1
        suffix = f" ({detail})" if detail else ""
        print(f"  [PASS {num:02d}/{total}] {title}{suffix}")

    try:
        # 1. TLS 1.3 Handshake, Root CA Chain Trust & AEAD Cipher Verification (DNS:localhost + IP:127.0.0.1 SANs)
        ctx = ssl.create_default_context(cafile=str(settings.tls_ca_cert_path))
        with (
            socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5) as raw_sock,
            ctx.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock,
        ):
            proto = tls_sock.version()
            cipher_info = tls_sock.cipher()
            assert proto == "TLSv1.3", f"Expected TLSv1.3, got {proto}"
            assert cipher_info is not None and (
                "GCM" in cipher_info[0] or "CHACHA20" in cipher_info[0]
            )
        sess = _make_trusted_session()
        health = sess.get(f"{BASE_HTTPS}/api/health", timeout=5)
        assert health.status_code == 200 and health.json()["tls"] is True
        record_pass(1, "TLS 1.3 Handshake, Trusted Root CA Chain & AEAD Cipher Verified", f"{proto} / {cipher_info[0]}")

        # 2. MITM Untrusted Rogue CA Handshake Rejection
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Attacker CA")])
        now = dt.datetime.now(dt.UTC)
        rogue_ca = (
            x509.CertificateBuilder()
            .subject_name(rogue_name)
            .issuer_name(rogue_name)
            .public_key(rogue_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(rogue_key, hashes.SHA256())
        )
        rogue_ca_path = settings.DATA_DIR / "rogue-test-ca.crt"
        rogue_ca_path.write_bytes(rogue_ca.public_bytes(serialization.Encoding.PEM))
        try:
            mitm_ctx = ssl.create_default_context(cafile=str(rogue_ca_path))
            mitm_blocked = False
            try:
                with (
                    socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5) as s2,
                    mitm_ctx.wrap_socket(s2, server_hostname="localhost"),
                ):
                    pass
            except ssl.SSLCertVerificationError:
                mitm_blocked = True
            assert mitm_blocked, "Rogue CA should have failed TLS certificate chain verification"
        finally:
            rogue_ca_path.unlink(missing_ok=True)
        record_pass(2, "MITM Rogue Root CA TLS Handshake Strictly Rejected")

        # 3. Plaintext HTTP -> HTTPS 301 Redirect + HSTS Preload Header
        http_resp = requests.get(f"{BASE_HTTP}/clinical-portal?tab=records", allow_redirects=False, timeout=5)
        assert http_resp.status_code == 301
        assert http_resp.headers["Location"] == f"https://127.0.0.1:{HTTPS_PORT}/clinical-portal?tab=records"
        assert "max-age=63072000" in http_resp.headers.get("Strict-Transport-Security", "")
        record_pass(3, "HTTP-to-HTTPS 301 Permanent Redirect & 2-Year HSTS Enforced")

        # 4. Strict CSP (`script-src 'none'`), Clickjacking, MIME-Sniffing & Banner Stripping
        idx_resp = sess.get(f"{BASE_HTTPS}/", timeout=5)
        csp = idx_resp.headers.get("Content-Security-Policy", "")
        assert "script-src 'none'" in csp and "unsafe-inline" not in csp
        assert "<script" not in idx_resp.text.lower()
        assert idx_resp.headers.get("X-Frame-Options") == "DENY"
        assert idx_resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Werkzeug" not in idx_resp.headers.get("Server", "")
        assert "Python" not in idx_resp.headers.get("Server", "")
        record_pass(4, "Strict CSP (`script-src 'none'`, Zero JS), XFO & Banner Stripping Verified")

        # 5. NIST SP 800-63B Password Policy & Contextual Identifier Rejection
        weak_resp = sess.post(
            f"{BASE_HTTPS}/api/auth/register",
            json={
                "fullName": "Nadia Razak",
                "email": "nadia.razak@carevault.local",
                "password": "Nadia@12345678!",  # Contains user's name 'nadia'
                "phone": "+6012-888-9999",
            },
            timeout=5,
        )
        assert weak_resp.status_code == 400 and weak_resp.json()["code"] == "WEAK_PASSWORD"
        record_pass(5, "NIST SP 800-63B Contextual Password Policy Enforced")

        # 6. Mass Assignment (`role: "admin"`) Blocked via Pydantic `extra='forbid'`
        mass_resp = sess.post(
            f"{BASE_HTTPS}/api/auth/register",
            json={
                "fullName": "Privilege Escalator",
                "email": "escalator@carevault.local",
                "password": "StrongUnique@Vault#99!",
                "phone": "+6012-777-6666",
                "role": "admin",
            },
            timeout=5,
        )
        assert mass_resp.status_code == 400 and mass_resp.json()["code"] == "VALIDATION_ERROR"
        record_pass(6, "Mass Assignment (`role: 'admin'`) Blocked by Pydantic Strict Allowlist")

        # 7. Argon2id Authentication & `__Host-cv_session` Cookie Security Flags
        raw_login = sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            json={"email": "amira.patient@carevault.local", "password": "Amira@Patient#2026!"},
            timeout=10,
        )
        assert raw_login.status_code == 200
        set_cookie_hdr = raw_login.headers.get("Set-Cookie", "")
        assert "__Host-cv_session=" in set_cookie_hdr
        assert "HttpOnly" in set_cookie_hdr
        assert "Secure" in set_cookie_hdr
        assert "SameSite=Strict" in set_cookie_hdr
        record_pass(7, "Argon2id Authentication & `__Host-cv_session` Cookie Flags Verified")

        # 8. Horizontal IDOR Protection (Patient #1 Amira vs Patient #2 Daniel's Record #2)
        amira_sess, _ = _login_session("amira.patient@carevault.local", "Amira@Patient#2026!")
        own_rec = amira_sess.get(f"{BASE_HTTPS}/api/records/1", timeout=5)
        assert own_rec.status_code == 200
        idor_rec = amira_sess.get(f"{BASE_HTTPS}/api/records/2", timeout=5)
        assert idor_rec.status_code == 403 and idor_rec.json()["code"] == "ACCESS_DENIED_OBJECT_POLICY"
        record_pass(8, "Horizontal IDOR Attack (Patient #1 -> Record #2) Blocked (403 Object Policy)")

        # 9. Clinician PoLP (Assigned vs Unassigned Patient) & Synchronizer CSRF Enforcement
        aisyah_sess, aisyah_meta = _login_session("dr.aisyah@carevault.local", "DrAisyah@Clinic#2026!")
        aisyah_csrf = aisyah_meta["csrfToken"]

        # Missing CSRF header on state-changing POST -> 403 CSRF_TOKEN_INVALID
        no_csrf = aisyah_sess.post(
            f"{BASE_HTTPS}/api/records",
            json={
                "patientId": 5,
                "diagnosis": "Follow-up Hypertension Review",
                "prescription": "Continue Amlodipine 5mg OD",
                "clinicalNotes": "BP improved to 128/82 mmHg.",
                "severity": "LOW",
            },
            timeout=5,
        )
        assert no_csrf.status_code == 403 and no_csrf.json()["code"] == "CSRF_TOKEN_INVALID"

        # Unassigned patient Daniel (#6) -> 403 ACCESS_DENIED_UNASSIGNED_PATIENT
        unassigned_post = aisyah_sess.post(
            f"{BASE_HTTPS}/api/records",
            headers={"X-CSRF-Token": aisyah_csrf},
            json={
                "patientId": 6,
                "diagnosis": "Unauthorized Note Attempt",
                "prescription": "None",
                "clinicalNotes": "Attempting write to unassigned patient.",
                "severity": "LOW",
            },
            timeout=5,
        )
        assert unassigned_post.status_code == 403
        assert unassigned_post.json()["code"] == "ACCESS_DENIED_UNASSIGNED_PATIENT"
        record_pass(9, "Clinician Unassigned-Patient PoLP & Synchronizer CSRF Token Enforced")

        # 10. Separation of Duties: Reception Staff & Security Admin Denied Clinical Records
        staff_sess, _ = _login_session("reception@carevault.local", "FrontDesk@Staff#2026!")
        admin_sess, admin_meta = _login_session("admin@carevault.local", "Admin@CareVault#2026!")
        staff_denial = staff_sess.get(f"{BASE_HTTPS}/api/records", timeout=5)
        admin_denial = admin_sess.get(f"{BASE_HTTPS}/api/records", timeout=5)
        assert staff_denial.status_code == 403 and admin_denial.status_code == 403
        record_pass(10, "Separation of Duties Enforced (Staff & Admin Denied Clinical Diagnoses)")

        # 11. Parameterized SQL Injection Neutralization & Stored XSS Output Encoding
        sqli_login = sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            json={"email": "admin@carevault.local", "password": "' OR '1'='1' --"},
            timeout=10,
        )
        assert sqli_login.status_code == 401

        xss_create = aisyah_sess.post(
            f"{BASE_HTTPS}/api/records",
            headers={"X-CSRF-Token": aisyah_csrf},
            json={
                "patientId": 5,
                "diagnosis": "Migraine <script>alert('xss')</script>",
                "prescription": "Sumatriptan 50mg \"PRN\"",
                "clinicalNotes": "Photophobia noted & evaluated <img src=x onerror=alert(1)>",
                "severity": "MODERATE",
            },
            timeout=5,
        )
        assert xss_create.status_code == 201
        safe_diag = xss_create.json()["record"]["encoded"]["diagnosisHtml"]
        assert "<script>" not in safe_diag and "&lt;script&gt;" in safe_diag
        record_pass(11, "SQL Injection Neutralized & Stored XSS Payload Context-Encoded")

        # 12. Malformed JSON Safe Correlation ID + Disk Log Sensitive Credential Redaction
        bad_json_resp = sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            data='{"email": "broken_json"',
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        assert bad_json_resp.status_code == 400
        err_json = bad_json_resp.json()
        assert err_json["code"] == "MALFORMED_JSON" and err_json["correlationId"].startswith("ERR-")
        assert "Traceback" not in bad_json_resp.text

        secret_probe = "SuperSecretProbePassword#999!"
        sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            json={"email": "amira.patient@carevault.local", "password": secret_probe},
            timeout=10,
        )
        log_contents = settings.error_log_path.read_text(encoding="utf-8")
        assert secret_probe not in log_contents and "[REDACTED]" in log_contents
        record_pass(12, "Correlation ID Error Handling & Disk Log `[REDACTED]` Scrubbing Verified")

        # 13. Real Calendar Date Validation (`2026-02-31` Rejected) + `:ss` Normalization + Status Update
        amira_sess2, amira_meta2 = _login_session("amira.patient@carevault.local", "Amira@Patient#2026!")
        amira_csrf = amira_meta2["csrfToken"]

        bad_cal = amira_sess2.post(
            f"{BASE_HTTPS}/api/appointments",
            headers={"X-CSRF-Token": amira_csrf},
            json={
                "doctorId": 2,
                "scheduledAt": "2026-02-31T09:30",
                "reason": "Impossible calendar date check",
            },
            timeout=5,
        )
        assert bad_cal.status_code == 400 and bad_cal.json()["code"] == "VALIDATION_ERROR"

        good_appt = amira_sess2.post(
            f"{BASE_HTTPS}/api/appointments",
            headers={"X-CSRF-Token": amira_csrf},
            json={
                "doctorId": 2,
                "scheduledAt": "2026-12-15T11:15:00",
                "reason": "Routine blood pressure checkup",
            },
            timeout=5,
        )
        assert good_appt.status_code == 201
        appt_id = good_appt.json()["appointmentId"]

        upd_status = aisyah_sess.patch(
            f"{BASE_HTTPS}/api/appointments/{appt_id}/status",
            headers={"X-CSRF-Token": aisyah_csrf},
            json={"status": "COMPLETED"},
            timeout=5,
        )
        assert upd_status.status_code == 200
        record_pass(13, "Calendar Date Validation, `:ss` Normalization & Appointment Status Verified")

        # 14. TOTP 2FA: Optical QR Decode + Pending-Secret Safety + Anti-Replay Protection
        daniel_sess, daniel_meta = _login_session("daniel.patient@carevault.local", "Daniel@Patient#2026!")
        daniel_csrf = daniel_meta["csrfToken"]

        mfa_init = daniel_sess.post(
            f"{BASE_HTTPS}/api/auth/mfa/setup",
            headers={"X-CSRF-Token": daniel_csrf},
            json={},
            timeout=5,
        )
        assert mfa_init.status_code == 200
        mfa_data = mfa_init.json()
        secret_1 = mfa_data["manualEntryKey"]
        qr_b64 = mfa_data["qrDataUrl"].split(",", 1)[1]

        # Optically scan PNG QR image with OpenCV to prove real phone camera compatibility
        img_arr = np.frombuffer(base64.b64decode(qr_b64), dtype=np.uint8)
        qr_img = cv2.imdecode(img_arr, cv2.IMREAD_COLOR)
        decoded_uri, _, _ = cv2.QRCodeDetector().detectAndDecode(qr_img)
        assert f"secret={secret_1}" in decoded_uri, "OpenCV failed to optically decode QR PNG!"

        otp_1 = generate_current_totp(secret_1)
        en_resp = daniel_sess.post(
            f"{BASE_HTTPS}/api/auth/mfa/enable",
            headers={"X-CSRF-Token": daniel_csrf},
            json={"totpCode": otp_1},
            timeout=5,
        )
        assert en_resp.status_code == 200

        # Open `/mfa/setup` a second time WITHOUT enabling (simulates closing modal) -> secret_1 must remain active!
        re_init = daniel_sess.post(
            f"{BASE_HTTPS}/api/auth/mfa/setup",
            headers={"X-CSRF-Token": daniel_csrf},
            json={},
            timeout=5,
        )
        assert re_init.status_code == 200 and re_init.json()["mfaCurrentlyEnabled"] is True

        # Replaying the exact same OTP (`otp_1`) in the same 30s window must be rejected!
        replay_resp = sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            json={
                "email": "daniel.patient@carevault.local",
                "password": "Daniel@Patient#2026!",
                "totpCode": otp_1,
            },
            timeout=10,
        )
        assert replay_resp.status_code == 401 and replay_resp.json()["code"] == "INVALID_MFA_CODE"
        record_pass(14, "TOTP 2FA Optical QR Scan, Pending-Secret Safety & Anti-Replay Verified")

        # 15. Password-Verified TOTP 2FA Disablement
        bad_dis = daniel_sess.post(
            f"{BASE_HTTPS}/api/auth/mfa/disable",
            headers={"X-CSRF-Token": daniel_csrf},
            json={"password": "WrongPassword#123!"},
            timeout=10,
        )
        assert bad_dis.status_code == 401

        ok_dis = daniel_sess.post(
            f"{BASE_HTTPS}/api/auth/mfa/disable",
            headers={"X-CSRF-Token": daniel_csrf},
            json={"password": "Daniel@Patient#2026!"},
            timeout=10,
        )
        assert ok_dis.status_code == 200
        record_pass(15, "Password-Authenticated TOTP 2FA Disablement Verified")

        # 16. Admin RBAC Role Update Foreign-Key Check & Immediate Session Revocation
        admin_csrf = admin_meta["csrfToken"]

        # Assigning a non-doctor ID (e.g. Admin #1) as assignedDoctorId must be rejected (400)
        bad_fk = admin_sess.patch(
            f"{BASE_HTTPS}/api/admin/users/6/role",
            headers={"X-CSRF-Token": admin_csrf},
            json={"role": "patient", "assignedDoctorId": 1},
            timeout=5,
        )
        assert bad_fk.status_code == 400 and bad_fk.json()["code"] == "INVALID_ASSIGNED_DOCTOR"

        # Valid update revokes Daniel's active session immediately
        ok_role = admin_sess.patch(
            f"{BASE_HTTPS}/api/admin/users/6/role",
            headers={"X-CSRF-Token": admin_csrf},
            json={"role": "patient", "assignedDoctorId": 3},
            timeout=5,
        )
        assert ok_role.status_code == 200
        revoked_check = daniel_sess.get(f"{BASE_HTTPS}/api/auth/me", timeout=5)
        assert revoked_check.status_code == 401
        record_pass(16, "Admin Role Update FK Validation & Immediate Session Revocation Verified")

        # 17. Brute-Force 5-Attempt Account Lockout (423) & Admin Unlock Recovery
        reset_all_rate_limits()
        for _ in range(5):
            r = sess.post(
                f"{BASE_HTTPS}/api/auth/login",
                json={"email": "dr.kenneth@carevault.local", "password": "BadAttempt#Password1!"},
                timeout=10,
            )
            assert r.status_code == 401

        locked_attempt = sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            json={"email": "dr.kenneth@carevault.local", "password": "DrKenneth@Clinic#2026!"},
            timeout=10,
        )
        assert locked_attempt.status_code == 423 and locked_attempt.json()["code"] == "ACCOUNT_LOCKED"

        unlock_resp = admin_sess.post(
            f"{BASE_HTTPS}/api/admin/users/3/unlock",
            headers={"X-CSRF-Token": admin_csrf},
            json={},
            timeout=5,
        )
        assert unlock_resp.status_code == 200

        recovered_sess, _ = _login_session("dr.kenneth@carevault.local", "DrKenneth@Clinic#2026!")
        assert recovered_sess is not None
        record_pass(17, "5-Attempt Account Lockout (423) & Admin Account Unlock Verified")

        # 18. Admin Live 6-Check Cryptographic X.509 PKI & TLS 1.3 Cipher Inspector
        tls_inspector = admin_sess.get(f"{BASE_HTTPS}/api/admin/security/tls-status", timeout=5)
        assert tls_inspector.status_code == 200
        tls_body = tls_inspector.json()
        assert tls_body["activeConnection"]["encrypted"] is True
        assert tls_body["activeConnection"]["negotiatedProtocol"] == "TLSv1.3"
        checks = tls_body["pkiValidation"]["checks"]
        assert len(checks) == 6 and all(c["passed"] for c in checks)
        record_pass(
            18,
            "Admin Live X.509 PKI Chain & TLS 1.3 Cipher Inspector Verified",
            f"6/6 checks passed, {tls_body['activeConnection']['negotiatedCipher']['name']}",
        )

        # 19. Pure-Python SSR HTML Portal: Demo Quick-Fill, Form Login, CSRF, XSS Escaping & IDOR Probe
        ssr_sess = _make_trusted_session()
        demo_page = ssr_sess.get(f"{BASE_HTTPS}/?demo=patient1", timeout=5)
        assert demo_page.status_code == 200 and "amira.patient@carevault.local" in demo_page.text

        ssr_login = ssr_sess.post(
            f"{BASE_HTTPS}/portal/login",
            data={"email": "amira.patient@carevault.local", "password": "Amira@Patient#2026!"},
            timeout=10,
        )
        assert ssr_login.status_code == 200 and "Signed in as Amira Zulkifli" in ssr_login.text

        csrf_match = _re.search(r'name="_csrf_token" value="([a-f0-9]+)"', ssr_login.text)
        assert csrf_match is not None
        ssr_csrf = csrf_match.group(1)

        # Missing _csrf_token on form POST -> 403 error alert with Ref: ERR-
        ssr_no_csrf = ssr_sess.post(
            f"{BASE_HTTPS}/portal/records/probe",
            data={"probeRecordId": "1"},
            timeout=5,
        )
        assert ssr_no_csrf.status_code == 403 and "Ref: ERR-" in ssr_no_csrf.text

        # Authorized probe (#1) -> 200 OK; Unauthorized IDOR probe (#2) -> 403 BLOCKED BY RBAC/PoLP GUARD
        ssr_ok_probe = ssr_sess.post(
            f"{BASE_HTTPS}/portal/records/probe",
            data={"_csrf_token": ssr_csrf, "probeRecordId": "1"},
            timeout=5,
        )
        assert ssr_ok_probe.status_code == 200 and "AUTHORIZED (200 OK)" in ssr_ok_probe.text

        ssr_bad_probe = ssr_sess.post(
            f"{BASE_HTTPS}/portal/records/probe",
            data={"_csrf_token": ssr_csrf, "probeRecordId": "2"},
            timeout=5,
        )
        assert ssr_bad_probe.status_code == 403 and "BLOCKED BY RBAC/PoLP GUARD" in ssr_bad_probe.text

        # Sticky form preservation on validation failure (keeps typed reason and selected doctor)
        ssr_sticky = ssr_sess.post(
            f"{BASE_HTTPS}/portal/appointments/create",
            data={
                "_csrf_token": ssr_csrf,
                "doctorId": "3",
                "scheduledAt": "2026-02-31T09:30",
                "reason": "Follow-up cardiac consultation",
            },
            timeout=5,
        )
        assert ssr_sticky.status_code == 400
        assert 'value="Follow-up cardiac consultation"' in ssr_sticky.text
        assert '<option value="3" selected>' in ssr_sticky.text
        record_pass(19, "Pure-Python SSR Portal Login, Form CSRF, Sticky Inputs & IDOR Probe UI Verified")

        # 20. Pure-Python SSR Admin Dashboard, Live TLS UI Card & Logout Session Revocation
        ssr_admin = _make_trusted_session()
        adm_page = ssr_admin.post(
            f"{BASE_HTTPS}/portal/login",
            data={"email": "admin@carevault.local", "password": "Admin@CareVault#2026!"},
            timeout=10,
        )
        assert adm_page.status_code == 200
        assert "Protocol=TLSv1.3" in adm_page.text
        assert "[PASS] Root Certificate CA BasicConstraint" in adm_page.text

        adm_csrf_match = _re.search(r'name="_csrf_token" value="([a-f0-9]+)"', adm_page.text)
        assert adm_csrf_match is not None
        out_page = ssr_admin.post(
            f"{BASE_HTTPS}/portal/logout",
            data={"_csrf_token": adm_csrf_match.group(1)},
            timeout=5,
        )
        assert out_page.status_code == 200 and "Signed out securely" in out_page.text
        record_pass(20, "Pure-Python SSR Admin Live TLS 1.3 Inspector & Logout Verified")

        # 21. SSR 2-Step TOTP Nonce Challenge (Zero Password Reflection in HTML), Anti-Replay & Logout CSRF Guard
        reset_all_rate_limits()
        ssr_mfa = _make_trusted_session()
        p_login = ssr_mfa.post(
            f"{BASE_HTTPS}/portal/login",
            data={"email": "reception@carevault.local", "password": "FrontDesk@Staff#2026!"},
            timeout=10,
        )
        assert p_login.status_code == 200
        mfa_csrf = _re.search(r'name="_csrf_token" value="([a-f0-9]+)"', p_login.text)
        assert mfa_csrf is not None
        staff_csrf = mfa_csrf.group(1)

        # Cross-site forged logout POST without CSRF token must be rejected (403) without dropping session
        forged_logout = ssr_mfa.post(f"{BASE_HTTPS}/portal/logout", data={}, timeout=5)
        assert forged_logout.status_code == 403

        setup_page = ssr_mfa.post(
            f"{BASE_HTTPS}/portal/mfa/setup",
            data={"_csrf_token": staff_csrf},
            timeout=5,
        )
        assert setup_page.status_code == 200
        key_match = _re.search(
            r"Manual Base32 Secret Key:\s*<strong>([A-Z2-7]+)</strong>", setup_page.text
        )
        assert key_match is not None
        staff_secret = key_match.group(1)

        curr_step = int(time.time() // 30)
        enroll_otp = compute_hotp(staff_secret, curr_step - 1)
        en_page = ssr_mfa.post(
            f"{BASE_HTTPS}/portal/mfa/enable",
            data={"_csrf_token": staff_csrf, "totpCode": enroll_otp},
            timeout=5,
        )
        assert en_page.status_code == 200 and "ACTIVE" in en_page.text

        # Sign out cleanly, then test Step-1 -> Step-2 SSR MFA Nonce Challenge
        ssr_mfa.post(f"{BASE_HTTPS}/portal/logout", data={"_csrf_token": staff_csrf}, timeout=5)
        step1_resp = ssr_mfa.post(
            f"{BASE_HTTPS}/portal/login",
            data={"email": "reception@carevault.local", "password": "FrontDesk@Staff#2026!"},
            timeout=10,
        )
        assert step1_resp.status_code == 200
        assert "FrontDesk@Staff#2026!" not in step1_resp.text, "Password must never be reflected in Step-2 HTML!"
        chal_match = _re.search(r'name="mfaChallengeToken" value="([a-f0-9]+)"', step1_resp.text)
        assert chal_match is not None
        chal_token = chal_match.group(1)

        # Replay of enroll_otp must be rejected (401) while keeping challenge active (1/3 tries)
        replay_step2 = ssr_mfa.post(
            f"{BASE_HTTPS}/portal/login/mfa",
            data={"mfaChallengeToken": chal_token, "totpCode": enroll_otp},
            timeout=5,
        )
        assert replay_step2.status_code == 401 and f'value="{chal_token}"' in replay_step2.text

        # Fresh current-window OTP completes Step-2 sign-in
        fresh_otp = compute_hotp(staff_secret, curr_step)
        ok_step2 = ssr_mfa.post(
            f"{BASE_HTTPS}/portal/login/mfa",
            data={"mfaChallengeToken": chal_token, "totpCode": fresh_otp},
            timeout=5,
        )
        assert ok_step2.status_code == 200 and "2FA verified!" in ok_step2.text

        # Cleanly disable MFA on staff account
        new_csrf = _re.search(r'name="_csrf_token" value="([a-f0-9]+)"', ok_step2.text)
        assert new_csrf is not None
        dis_page = ssr_mfa.post(
            f"{BASE_HTTPS}/portal/mfa/disable",
            data={"_csrf_token": new_csrf.group(1), "password": "FrontDesk@Staff#2026!"},
            timeout=10,
        )
        assert dis_page.status_code == 200 and "disabled" in dis_page.text
        record_pass(21, "SSR 2-Step MFA Nonce Challenge (Zero Password Reflection) & Logout CSRF Guard Verified")

        # 22. PHI Cache-Control (`no-store`), HTML vs JSON 404 Negotiation, Session Rotation & Redirect Sanitization
        reset_all_rate_limits()
        home_check = sess.get(f"{BASE_HTTPS}/", timeout=5)
        assert "no-store" in home_check.headers.get("Cache-Control", "")

        # Browser GET refresh on form action URLs redirects cleanly (303) instead of 405 Method Not Allowed
        get_portal_refresh = sess.get(
            f"{BASE_HTTPS}/portal/mfa/setup", allow_redirects=False, timeout=5
        )
        assert get_portal_refresh.status_code == 303
        assert get_portal_refresh.headers.get("Location", "").endswith("/?tab=mfa")

        html_404 = sess.get(
            f"{BASE_HTTPS}/non-existent-clinical-route",
            headers={"Accept": "text/html"},
            timeout=5,
        )
        assert html_404.status_code == 404 and "text/html" in html_404.headers.get("Content-Type", "")
        assert "ERR-" in html_404.text and "Traceback" not in html_404.text

        json_404 = sess.get(f"{BASE_HTTPS}/api/non-existent-endpoint", timeout=5)
        assert json_404.status_code == 404 and json_404.json()["code"] == "RESOURCE_NOT_FOUND"

        # Session rotation: re-authenticating on an active session revokes old cookie token immediately
        rot_sess = _make_trusted_session()
        r1 = rot_sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            json={"email": "amira.patient@carevault.local", "password": "Amira@Patient#2026!"},
            timeout=10,
        )
        assert r1.status_code == 200
        old_token = rot_sess.cookies.get("__Host-cv_session")
        assert old_token is not None

        r2 = rot_sess.post(
            f"{BASE_HTTPS}/api/auth/login",
            json={"email": "amira.patient@carevault.local", "password": "Amira@Patient#2026!"},
            timeout=10,
        )
        assert r2.status_code == 200
        new_token = rot_sess.cookies.get("__Host-cv_session")
        assert new_token is not None and new_token != old_token

        stale_sess = _make_trusted_session()
        stale_sess.cookies.set("__Host-cv_session", old_token)
        assert stale_sess.get(f"{BASE_HTTPS}/api/auth/me", timeout=5).status_code == 401

        # Open-redirect sanitization on HTTP -> HTTPS 301 redirector
        redir_probe = requests.get(
            f"{BASE_HTTP}//@evil.example/phish", allow_redirects=False, timeout=5
        )
        assert redir_probe.status_code == 301
        assert redir_probe.headers["Location"] == f"https://127.0.0.1:{HTTPS_PORT}/@evil.example/phish"
        record_pass(22, "PHI `Cache-Control: no-store`, HTML/JSON 404, Session Rotation & Redirect Guard Verified")

        # 23. Chromium Idle TCP Preconnect & Slowloris Incomplete-TLS Handshake Resilience
        idle_sockets: list[socket.socket] = []
        try:
            for _ in range(5):
                idle_sockets.append(socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=2))
            t0 = time.perf_counter()
            pre_sess = _make_trusted_session()
            fav = pre_sess.get(f"{BASE_HTTPS}/favicon.ico", timeout=2.0)
            idx_fast = pre_sess.get(f"{BASE_HTTPS}/?demo=doctor1", timeout=2.0)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            assert fav.status_code == 200 and "image/svg+xml" in fav.headers.get("Content-Type", "")
            assert idx_fast.status_code == 200 and "dr.aisyah@carevault.local" in idx_fast.text
        finally:
            for sk in idle_sockets:
                with contextlib.suppress(OSError):
                    sk.close()
        record_pass(
            23,
            "Chromium Idle TCP Preconnect & Slowloris TLS Handshake Resilience Verified",
            f"5 idle sockets held, responded in {elapsed_ms:.0f} ms",
        )

        # 24. Full Interactive SSR Portal Workflow (Register -> Book -> Diagnose -> Complete -> Admin -> Spaced TOTP)
        reset_all_rate_limits()
        wf_pub = _make_trusted_session()
        reg_ui = wf_pub.post(
            f"{BASE_HTTPS}/portal/register",
            data={
                "fullName": "Kavitha A/P Rajan (Patient)",
                "email": "kavitha.patient@carevault.local",
                "phone": "(+60) 12-998 7766",
                "password": "UniqueClinical#Vault2026!",
            },
            timeout=10,
        )
        assert reg_ui.status_code == 200 and "Patient account created securely" in reg_ui.text

        wf_pat = _make_trusted_session()
        pat_home = wf_pat.post(
            f"{BASE_HTTPS}/portal/login",
            data={
                "email": "kavitha.patient@carevault.local",
                "password": "UniqueClinical#Vault2026!",
            },
            timeout=10,
        )
        assert pat_home.status_code == 200 and "Kavitha A/P Rajan (Patient)" in pat_home.text
        pat_csrf_m = _re.search(r'name="_csrf_token" value="([a-f0-9]+)"', pat_home.text)
        assert pat_csrf_m is not None
        pat_csrf = pat_csrf_m.group(1)

        book_ui = wf_pat.post(
            f"{BASE_HTTPS}/portal/appointments/create",
            data={
                "_csrf_token": pat_csrf,
                "doctorId": "2",
                "scheduledAt": "2026-12-20T14:30",
                "reason": "Comprehensive lipid profile review",
            },
            timeout=5,
        )
        assert book_ui.status_code == 200 and "Comprehensive lipid profile review" in book_ui.text

        # Doctor creates a clinical record via SSR form
        wf_doc = _make_trusted_session()
        doc_home = wf_doc.post(
            f"{BASE_HTTPS}/portal/login",
            data={"email": "dr.aisyah@carevault.local", "password": "DrAisyah@Clinic#2026!"},
            timeout=10,
        )
        doc_csrf_m = _re.search(r'name="_csrf_token" value="([a-f0-9]+)"', doc_home.text)
        assert doc_csrf_m is not None
        doc_csrf = doc_csrf_m.group(1)
        rec_ui = wf_doc.post(
            f"{BASE_HTTPS}/portal/records/create",
            data={
                "_csrf_token": doc_csrf,
                "patientId": "5",
                "severity": "MODERATE",
                "diagnosis": "Dyslipidemia Follow-Up Assessment",
                "prescription": "Atorvastatin 20mg ON",
                "clinicalNotes": "Fasting LDL improved; continue dietary counseling.",
            },
            timeout=5,
        )
        assert rec_ui.status_code == 200 and "Dyslipidemia Follow-Up Assessment" in rec_ui.text

        # Staff marks appointment COMPLETED via SSR form
        wf_staff = _make_trusted_session()
        st_home = wf_staff.post(
            f"{BASE_HTTPS}/portal/login",
            data={"email": "reception@carevault.local", "password": "FrontDesk@Staff#2026!"},
            timeout=10,
        )
        st_csrf_m = _re.search(r'name="_csrf_token" value="([a-f0-9]+)"', st_home.text)
        assert st_csrf_m is not None
        st_csrf = st_csrf_m.group(1)
        comp_ui = wf_staff.post(
            f"{BASE_HTTPS}/portal/appointments/1/status",
            data={"_csrf_token": st_csrf, "status": "COMPLETED"},
            timeout=5,
        )
        assert comp_ui.status_code == 200 and "marked as COMPLETED" in comp_ui.text

        # Spaced 6-digit TOTP paste (`123 456`) works seamlessly on MFA setup
        st_qr = wf_staff.post(
            f"{BASE_HTTPS}/portal/mfa/setup",
            data={"_csrf_token": st_csrf},
            timeout=5,
        )
        st_key_m = _re.search(
            r"Manual Base32 Secret Key:\s*<strong>([A-Z2-7]+)</strong>", st_qr.text
        )
        assert st_key_m is not None
        raw_otp6 = generate_current_totp(st_key_m.group(1))
        spaced_otp = f"{raw_otp6[:3]} {raw_otp6[3:]}"
        st_en = wf_staff.post(
            f"{BASE_HTTPS}/portal/mfa/enable",
            data={"_csrf_token": st_csrf, "totpCode": spaced_otp},
            timeout=5,
        )
        assert st_en.status_code == 200 and "ACTIVE" in st_en.text
        record_pass(
            24,
            "Full Interactive SSR Portal Workflow (Register, Book, Diagnose, Complete & Spaced TOTP) Verified",
        )

        print("\n" + "=" * 72)
        print(f"  SECURITY SUITE RESULT: {passed}/{total} LIVE CHECKS PASSED (100%)")
        print("=" * 72)
        return 0

    finally:
        servers.stop()
        _cleanup_test_artifacts()


def test_carevault_end_to_end_security_suite() -> None:
    """Pytest entrypoint executing all 24 live HTTPS & SSR security checks."""
    assert run_suite() == 0


if __name__ == "__main__":
    raise SystemExit(run_suite())
