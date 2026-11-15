"""
CareVault Database Seeder (`carevault/seed.py`)
Provisions the 6 RBAC demonstration accounts (Admin, 2 Doctors, Reception Staff, 2 Patients),
initial clinical records, and scheduled appointments using Argon2id password hashes.
"""
from __future__ import annotations

import datetime as dt
from typing import TypedDict

from carevault.database import execute_write, get_connection, query_one
from carevault.security.password import hash_password


class DemoAccount(TypedDict):
    full_name: str
    email: str
    phone: str
    password: str
    role: str
    assigned_doctor_email: str | None


DEMO_ACCOUNTS: list[DemoAccount] = [
    {
        "full_name": "System Security Admin",
        "email": "admin@carevault.local",
        "phone": "+6012-300-1000",
        "password": "Admin@CareVault#2026!",
        "role": "admin",
        "assigned_doctor_email": None,
    },
    {
        "full_name": "Dr. Aisyah Rahman",
        "email": "dr.aisyah@carevault.local",
        "phone": "+6012-300-2001",
        "password": "DrAisyah@Clinic#2026!",
        "role": "doctor",
        "assigned_doctor_email": None,
    },
    {
        "full_name": "Dr. Kenneth Lim",
        "email": "dr.kenneth@carevault.local",
        "phone": "+6012-300-2002",
        "password": "DrKenneth@Clinic#2026!",
        "role": "doctor",
        "assigned_doctor_email": None,
    },
    {
        "full_name": "Siti Nurhaliza (Front Desk)",
        "email": "reception@carevault.local",
        "phone": "+6012-300-3001",
        "password": "FrontDesk@Staff#2026!",
        "role": "staff",
        "assigned_doctor_email": None,
    },
    {
        "full_name": "Amira Zulkifli",
        "email": "amira.patient@carevault.local",
        "phone": "+6012-400-5001",
        "password": "Amira@Patient#2026!",
        "role": "patient",
        "assigned_doctor_email": "dr.aisyah@carevault.local",
    },
    {
        "full_name": "Daniel Tan",
        "email": "daniel.patient@carevault.local",
        "phone": "+6012-400-5002",
        "password": "Daniel@Patient#2026!",
        "role": "patient",
        "assigned_doctor_email": "dr.kenneth@carevault.local",
    },
]


def seed_database(force_reset: bool = False) -> dict[str, int]:
    conn = get_connection()
    if force_reset:
        conn.executescript(
            """
            DELETE FROM appointments;
            DELETE FROM clinical_records;
            DELETE FROM sessions;
            DELETE FROM users;
            """
        )
        has_seq = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"
        ).fetchone()
        if has_seq:
            conn.execute("DELETE FROM sqlite_sequence;")
        conn.commit()

    existing_count = query_one("SELECT COUNT(*) AS cnt FROM users")
    if existing_count and existing_count["cnt"] > 0:
        return {"users": existing_count["cnt"], "seeded": 0}

    email_to_id: dict[str, int] = {}

    for acct in DEMO_ACCOUNTS:
        assigned_doc_id = (
            email_to_id.get(acct["assigned_doctor_email"])
            if acct["assigned_doctor_email"]
            else None
        )
        pwd_hash = hash_password(acct["password"])
        uid = execute_write(
            """
            INSERT INTO users (full_name, email, phone, password_hash, role, assigned_doctor_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                acct["full_name"],
                acct["email"],
                acct["phone"],
                pwd_hash,
                acct["role"],
                assigned_doc_id,
            ),
        )
        email_to_id[acct["email"]] = uid

    amira_id = email_to_id["amira.patient@carevault.local"]
    daniel_id = email_to_id["daniel.patient@carevault.local"]
    aisyah_id = email_to_id["dr.aisyah@carevault.local"]
    kenneth_id = email_to_id["dr.kenneth@carevault.local"]

    execute_write(
        """
        INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            amira_id,
            aisyah_id,
            "Essential Hypertension (Stage 1) - ICD-10 I10",
            "Amlodipine 5mg PO once daily; Low-sodium DASH dietary regimen",
            "Resting BP 144/92 mmHg across two visits. ECG normal sinus rhythm. Follow-up blood panel in 4 weeks.",
            "MODERATE",
        ),
    )

    execute_write(
        """
        INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            daniel_id,
            kenneth_id,
            "Acute Allergic Rhinitis & Mild Bronchospasm",
            "Cetirizine 10mg nocte + Salbutamol MDI 100mcg PRN",
            "Triggered by seasonal dust exposure. SpO2 99% on room air. Chest auscultation clear post-bronchodilator.",
            "LOW",
        ),
    )

    base_day = (dt.datetime.now(dt.UTC) + dt.timedelta(days=3)).strftime("%Y-%m-%d")
    second_day = (dt.datetime.now(dt.UTC) + dt.timedelta(days=5)).strftime("%Y-%m-%d")

    execute_write(
        """
        INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status)
        VALUES (?, ?, ?, ?, 'SCHEDULED')
        """,
        (
            amira_id,
            aisyah_id,
            f"{base_day}T10:30",
            "4-week antihypertensive titration & renal function review",
        ),
    )

    execute_write(
        """
        INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status)
        VALUES (?, ?, ?, ?, 'SCHEDULED')
        """,
        (
            daniel_id,
            kenneth_id,
            f"{second_day}T14:00",
            "Spirometry follow-up and allergy management review",
        ),
    )

    print(
        f"[SEED] SUCCESS: Seeded {len(DEMO_ACCOUNTS)} RBAC accounts, 2 clinical records, and 2 appointments."
    )
    return {"users": len(DEMO_ACCOUNTS), "seeded": 1}

