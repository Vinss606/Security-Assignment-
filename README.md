# CareVault — Secure Clinical & Patient Records Portal (100% Pure Python Edition)

**Module:** `6000CMD / 6005CEM` Security — CW2 Secure Application Development and Implementation  
**Tech Stack:** 100% Python (`Python 3.13`, `Flask 3.1` + Server-Side Jinja2 Templates, `Pydantic v2` `extra='forbid'`, PyCA `cryptography` Argon2id / AES-256-GCM / Two-Tier X.509v3 PKI, Parameterized `sqlite3` WAL) — **Zero JavaScript files (`CSP: script-src 'none'`)**  
**Implemented Scope:** Foundation System + **CLO1 (Host & Network Security)** + **CLO2** + **Project Requirements 1, 2, and 3** (with thread-safe `security_events` hooks in `carevault/security/extension_hooks.py` for Groupmates handling Requirements 4–6).

---

## Quick Start (Windows / macOS / Linux)

```powershell
cd carevault-app

# 1. Generate 2-Tier PKI (4096-bit Root CA + SAN Server Cert) & Seed RBAC Database
python manage.py setup

# 2. Start HTTPS (TLS 1.2/1.3) Portal on https://127.0.0.1:8443 (+ HTTP 301 Redirect on :8080)
python run.py
```

Open **`https://127.0.0.1:8443`** in your browser:
- **Recommended Local URL:** Use **`https://127.0.0.1:8443`** in Chrome/Edge (RFC 6797 exempts IP literals from HSTS lockout so you can immediately click *Advanced -> Proceed to 127.0.0.1* during local evaluation, or import `certs/carevault-root-ca.crt` into Windows *Trusted Root Certification Authorities* (`certmgr.msc`) for a green trusted padlock on both `https://127.0.0.1:8443` and `https://localhost:8443`).
- **IDE Run Button (`▷`):** You can run `run.py`, `carevault/__init__.py`, or `carevault/server.py` directly from VS Code / Antigravity.

---

## Run Live Automated Security & Penetration Verification Suite

```powershell
python tests/test_security_suite.py
```

Runs **24 end-to-end live HTTPS security & SSR UI tests** against an isolated test database over TLS 1.3 verifying Root CA chain trust, MITM rogue-CA rejection, HTTP-to-HTTPS `301` + HSTS redirect + open-redirect sanitization, strict `script-src 'none'` CSP (zero JS) + `Cache-Control: no-store`, NIST SP 800-63B contextual password policy, Pydantic `extra='forbid'` Mass Assignment blocking, Argon2id + `__Host-cv_session` flags + re-login session rotation, Horizontal IDOR blocking, Clinician PoLP + CSRF enforcement, Staff/Admin Separation of Duties, SQL Injection & Stored XSS encoding, `ERR-XXXXXXXX` Correlation ID + HTML/JSON error negotiation + `[REDACTED]` error logs, calendar date validation, OpenCV optical QR 2FA + anti-replay, 2-step SSR MFA challenge (zero password reflection in HTML), 5-attempt account lockout + Admin recovery, and 6-check X.509 PKI inspector.

---

## Pre-Seeded RBAC Demonstration Accounts

| Role | Email | Password | PoLP Scope Summary |
| :--- | :--- | :--- | :--- |
| **Security Admin** | `admin@carevault.local` | `Admin@CareVault#2026!` | Manages user roles, unlocks accounts, inspects live TLS/PKI chain. **Denied** clinical records (Separation of Duties). |
| **Doctor #1** | `dr.aisyah@carevault.local` | `DrAisyah@Clinic#2026!` | Reads/authors clinical records **only** for assigned patient Amira (`#5`). **Denied** Daniel's records (`#2`). |
| **Doctor #2** | `dr.kenneth@carevault.local` | `DrKenneth@Clinic#2026!` | Reads/authors clinical records **only** for assigned patient Daniel (`#6`). **Denied** Amira's records (`#1`). |
| **Reception Staff** | `reception@carevault.local` | `FrontDesk@Staff#2026!` | Schedules & manages clinic appointments. **Denied** all confidential clinical diagnoses/notes. |
| **Patient #1** | `amira.patient@carevault.local` | `Amira@Patient#2026!` | Reads **only** own clinical record (`#1`) & books own appointments. **Denied** Record `#2` (IDOR blocked). |
| **Patient #2** | `daniel.patient@carevault.local` | `Daniel@Patient#2026!` | Reads **only** own clinical record (`#2`) & books own appointments. **Denied** Record `#1` (IDOR blocked). |

---

## Host & Network-Level Deployment (CLO1 — Docker + Nginx Reverse Proxy)

```powershell
cd infra
docker compose up --build -d
```

- `nginx_edge`: Terminates external traffic on ports `80` (301 redirect) and `443` (TLS 1.2/1.3 AEAD ciphers), enforces IP rate-limiting zones (`auth_zone` & `api_zone`), strips version banners, runs with a read-only root filesystem, and verifies upstream TLS certificates against `carevault-root-ca.crt`.
- `carevault_app`: Built on `python:3.13-slim`, executes as unprivileged Linux user `carevault`, drops all kernel capabilities (`cap_drop: ALL`), sets `no-new-privileges:true`, publishes **zero host ports**, and resides exclusively on the isolated `internal_app_net` (`internal: true`) network.
