"""
Insecure Database Access Layer (carevault/database.py)
INTENTIONALLY VULNERABLE BASELINE:
- Uses raw string concatenation / direct string interpolation in SQL queries (demonstrating SQL Injection - CWE-89)
- Stores passwords using weak, unsalted MD5 (CWE-328 / CWE-916)
- Stores clinical records in plaintext without encryption at rest (CWE-311)
- Lacks foreign key enforcement and strict role validation
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from typing import Any

from carevault.config import DB_PATH

_thread_local = threading.local()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'patient',
    assigned_doctor_id INTEGER,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS clinical_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    diagnosis TEXT NOT NULL,
    prescription TEXT NOT NULL,
    clinical_notes TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'LOW',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    scheduled_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'SCHEDULED',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def weak_md5_hash(password: str) -> str:
    """Vulnerable weak hashing: Unsalted single-round MD5."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def get_connection(db_file: str | None = None) -> sqlite3.Connection:
    target = str(db_file or DB_PATH)
    conn = getattr(_thread_local, "conn", None)
    if conn is None or getattr(_thread_local, "db_file", None) != target:
        conn = sqlite3.connect(target, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Intentionally disable WAL and foreign keys
        conn.execute("PRAGMA foreign_keys = OFF;")
        _thread_local.conn = conn
        _thread_local.db_file = target
    return conn


def init_db(db_file: str | None = None) -> None:
    conn = get_connection(db_file)
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def raw_query_all(sql: str, db_file: str | None = None) -> list[dict[str, Any]]:
    """Vulnerable helper: Executes raw unparameterized SQL query."""
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(sql)
    return [dict(row) for row in cur.fetchall()]


def raw_query_one(sql: str, db_file: str | None = None) -> dict[str, Any] | None:
    """Vulnerable helper: Executes raw unparameterized SQL query."""
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(sql)
    row = cur.fetchone()
    return dict(row) if row else None


def raw_execute_write(sql: str, db_file: str | None = None) -> int:
    """Vulnerable helper: Executes raw unparameterized SQL statement and returns lastrowid."""
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    return cur.lastrowid or 0

