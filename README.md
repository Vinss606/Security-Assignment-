# CareVault — Insecure Baseline Clinical Portal (Vulnerable Edition)

> ⚠️ **EDUCATIONAL / VULNERABILITY DEMONSTRATION BASELINE**  
> This version of CareVault has been intentionally constructed **WITHOUT** security controls to serve as the baseline for **Module Learning Outcomes CLO1 and CLO2** in **6000CMD / 6005CEM CW2**.
> It demonstrates the critical vulnerabilities that the secured version (`carevault-app`) resolves.

---

## 1. Quick Start

### Prerequisites
- Python 3.10+ (tested with Python 3.13)
- `pip install flask`

### Launch the Insecure Application
```bash
cd .
python run.py
```
- Open browser at: **`http://127.0.0.1:5000`** (Plaintext HTTP, port 5000)

### Run the Automated Vulnerability Test Suite
```bash
python tests/test_vulnerabilities.py
```
*(Verifies all 9 vulnerabilities: SQLi, IDOR, Mass Assignment, Stored XSS, Insecure Cookies, Weak MD5, Missing Headers, No Lockout, and Verbose Traceback).*

---

## 2. Seeded Demonstration Accounts

| Role | Name | Email | Password | Assigned Doctor |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | System Security Admin | `admin@carevault.local` | `Admin@CareVault#2026!` | *None* |
| **Doctor** | Dr. Aisyah Rahman | `dr.aisyah@carevault.local` | `DrAisyah@Clinic#2026!` | *None* |
| **Doctor** | Dr. Kenneth Lim | `dr.kenneth@carevault.local` | `DrKenneth@Clinic#2026!` | *None* |
| **Staff** | Siti Nurhaliza (Front Desk) | `reception@carevault.local` | `FrontDesk@Staff#2026!` | *None* |
| **Patient** | Amira Zulkifli (ID #5) | `amira.patient@carevault.local` | `Amira@Patient#2026!` | Dr. Aisyah |
| **Patient** | Daniel Tan (ID #6) | `daniel.patient@carevault.local` | `Daniel@Patient#2026!` | Dr. Kenneth |

---

## 3. Step-by-Step Viva & Presentation Demonstration Guide

### Attack 1: SQL Injection (SQLi) Authentication Bypass (CWE-89)
1. On the login page (`http://127.0.0.1:5000`), enter:
   - **Email:** `' OR '1'='1' --`
   - **Password:** *anything*
2. Click **Sign In**.
3. **Outcome:** You are immediately authenticated as the first database user (**Administrator**) without needing a valid password!

### Attack 2: Horizontal Insecure Direct Object Reference (IDOR / BOLA) (CWE-639)
1. Log in as **Patient Amira** (`amira.patient@carevault.local` / ID #5).
2. Go to the URL: `http://127.0.0.1:5000/?tab=records&record_id=2` or click the button **"View Record #2 (Daniel)"**.
3. **Outcome:** Amira can view Daniel's confidential psychiatric diagnosis (*"Major Depressive Disorder"* and *"Escitalopram"* prescription). The server fails to enforce object-level ownership!

### Attack 3: Vertical Privilege Escalation via Mass Assignment (CWE-915)
1. In the **Patient Self-Registration** form on the home page, select **Role: `admin`** (or send `{"role": "admin"}` in JSON to `/api/auth/register`).
2. Complete registration and sign in.
3. **Outcome:** The new user is granted full `admin` role and can view all database user hashes and change permissions!

### Attack 4: Stored Cross-Site Scripting (XSS) (CWE-79)
1. Sign in as a clinician (or use the record creation form).
2. In the **Diagnosis** field, input:
   ```html
   Cardiology Check <script>alert('XSS Exploit Proof! Cookie: ' + document.cookie)</script>
   ```
3. Save the record and reload the Records tab.
4. **Outcome:** The `<script>` tag is rendered via `| safe` without HTML entity encoding, and the JavaScript alert executes immediately!

### Attack 5: Session Hijacking via Unprotected Cookies (CWE-1004 / CWE-614)
1. Open the browser Developer Tools (F12) -> **Console**.
2. Type:
   ```javascript
   console.log(document.cookie);
   ```
3. **Outcome:** The session token `cv_insecure_session` is displayed in plain text because it lacks the `HttpOnly` flag. Any XSS exploit can steal this session!

### Attack 6: Unsalted MD5 Password Hashes in Database (CWE-328)
1. Sign in as Admin and navigate to the **Admin Database Users** tab.
2. **Outcome:** Passwords are shown hashed using 32-character unsalted MD5 (e.g. `4c64904f3ec9d5ccfeaaf342bc022411`). These can be reversed within seconds using rainbow tables or online hash crackers.

### Attack 7: Plaintext HTTP Communication (CWE-319)
1. Inspect the URL bar or capture traffic with Wireshark.
2. **Outcome:** Traffic is transmitted over unencrypted HTTP port 5000. All patient records, diagnoses, and login credentials travel over the network in clear text.

---

## 4. Comparison Matrix: Insecure Baseline vs. Secure CareVault

| Security Domain | Insecure Baseline (`.`) | Secured Application (`carevault-app`) |
| :--- | :--- | :--- |
| **Transport** | Plaintext HTTP (Port 5000), No TLS, No HSTS | TLS 1.3 on Port 8443, Two-Tier X.509 PKI, 2-Year HSTS, HTTP 8080 Redirect |
| **Passwords** | Unsalted MD5 (32-char hex), no entropy policy | Argon2id (64 MiB RAM, 3 iterations, 4 lanes), NIST SP 800-63-4 policy |
| **2FA / MFA** | Omitted completely | Pure-Python RFC 6238 TOTP, AES-256-GCM encrypted secrets, replay guard |
| **SQL Queries** | Raw string concatenation (`f"SELECT ... '{input}'"`), SQLi | 100% Parameterized `?` placeholders via SQLite |
| **Access Control** | Broken Object Level Authorization (IDOR) on records | Two-tier RBAC + Row-level ownership check (`record.patient_id == user.id`) |
| **XSS Defense** | Unescaped HTML rendering (`| safe`), No CSP | Context-aware HTML entity encoding + Zero-JS CSP (`script-src 'none'`) |
| **CSRF Defense** | No CSRF tokens on state-changing forms | Random 256-bit synchronizer CSRF tokens validated via constant-time compare |
| **Cookies** | Lacks `HttpOnly`, `Secure`, and `SameSite` | `__Host-cv_session` with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/` |
| **Mass Assignment** | Directly binds client payload to database columns | Pydantic v2 strict schemas with `extra='forbid'` |
| **Account Lockout** | Unlimited brute-force attempts | 5-attempt / 15-minute lockout (HTTP 423 `ACCOUNT_LOCKED`) |
| **Error Handling** | `DEBUG=True`, leaks Python stack traces & secrets | Centralized `ERR-XXXXXXXX` Correlation IDs, redacted server-only logs |

