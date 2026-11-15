"""
Insecure Database Seeder (carevault/seed.py)
Seeds the identical 6 RBAC demonstration accounts, clinical records, and appointments,
using weak unsalted MD5 password hashes and plaintext clinical notes.
"""
from __future__ import annotations

import datetime as dt

from carevault.database import get_connection, init_db, weak_md5_hash

DEMO_ACCOUNTS = [
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


def seed_database(force_reset: bool = False, db_file: str | None = None) -> dict[str, int]:
    conn = get_connection(db_file)
    init_db(db_file)

    if force_reset:
        conn.executescript(
            """
            DELETE FROM clinical_records;
            DELETE FROM appointments;
            DELETE FROM sessions;
            DELETE FROM users;
            DELETE FROM sqlite_sequence WHERE name IN ('users', 'clinical_records', 'appointments', 'sessions');
            """
        )
        conn.commit()

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users;")
    if cur.fetchone()[0] > 0 and not force_reset:
        return {"users": 6, "records": 2, "appointments": 2}

    # Insert Users with weak MD5 passwords
    user_id_map: dict[str, int] = {}
    for acc in DEMO_ACCOUNTS:
        pwd_hash = weak_md5_hash(acc["password"])
        cur.execute(
            """
            INSERT INTO users (full_name, email, phone, password_hash, role)
            VALUES (?, ?, ?, ?, ?)
            """,
            (acc["full_name"], acc["email"], acc["phone"], pwd_hash, acc["role"]),
        )
        user_id_map[acc["email"]] = cur.lastrowid

    # Update assigned doctors
    for acc in DEMO_ACCOUNTS:
        doc_email = acc["assigned_doctor_email"]
        if doc_email and doc_email in user_id_map:
            doc_id = user_id_map[doc_email]
            u_id = user_id_map[acc["email"]]
            cur.execute("UPDATE users SET assigned_doctor_id = ? WHERE id = ?", (doc_id, u_id))

    # Insert Clinical Records (Unencrypted plaintext)
    amira_id = user_id_map["amira.patient@carevault.local"]
    daniel_id = user_id_map["daniel.patient@carevault.local"]
    dr_aisyah_id = user_id_map["dr.aisyah@carevault.local"]
    dr_kenneth_id = user_id_map["dr.kenneth@carevault.local"]

    cur.execute(
        """
        INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            amira_id,
            dr_aisyah_id,
            "Type 2 Diabetes Mellitus (Uncomplicated)",
            "Metformin 500mg BD with meals; Lifestyle diet modification.",
            "Patient reports steady fasting blood glucose. HbA1c 6.8%. Continue current regimen.",
            "MODERATE",
        ),
    )

    cur.execute(
        """
        INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            daniel_id,
            dr_kenneth_id,
            "Major Depressive Disorder (Recurrent)",
            "Escitalopram 10mg OD morning; Referral to outpatient CBT therapist.",
            "Confidential psychiatric consultation notes. Patient experiencing sleep disturbance.",
            "HIGH",
        ),
    )

    # Insert Appointments
    now = dt.datetime.now(dt.timezone.utc)
    t1 = (now + dt.timedelta(days=2, hours=3)).strftime("%Y-%m-%dT10:00:00")
    t2 = (now + dt.timedelta(days=5, hours=6)).strftime("%Y-%m-%dT14:30:00")

    cur.execute(
        """
        INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (amira_id, dr_aisyah_id, t1, "Routine HbA1c Blood Panel Follow-Up", "SCHEDULED"),
    )

    cur.execute(
        """
        INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (daniel_id, dr_kenneth_id, t2, "Medication Review & Psychotherapy Check-In", "SCHEDULED"),
    )

    conn.commit()
    print("[INSECURE SEED] Seeded 6 accounts (MD5), 2 records, and 2 appointments.")
    return {"users": 6, "records": 2, "appointments": 2}


if __name__ == "__main__":
    seed_database(force_reset=True)

