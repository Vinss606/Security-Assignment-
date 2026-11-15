"""
Requirement 1 & 2: Parameterized SQLite Data Access Layer (carevault/database.py)
- Uses 100% parameterized `?` queries via `sqlite3` to block SQL Injection (OWASP A03:2021)
- Enforces relational foreign keys (`PRAGMA foreign_keys = ON`) and strict role CHECK constraints
- Stores only HMAC-SHA256 digests of session tokens to neutralize session-table read leaks
- Thread-safe per-thread connection management supporting isolated test databases
"""
from __future__ import annotations

import contextlib
import sqlite3
import threading
from typing import Any

from carevault.config import settings

_thread_local = threading.local()
_all_conn_maps: list[dict[str, sqlite3.Connection]] = []
_initialized_paths: set[str] = set()
_init_lock = threading.Lock()
_write_lock = threading.RLock()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'patient' CHECK (role IN ('patient', 'staff', 'doctor', 'admin')),
    assigned_doctor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1)),
    mfa_secret_enc TEXT,
    mfa_pending_secret_enc TEXT,
    mfa_last_used_step INTEGER,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS clinical_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    diagnosis TEXT NOT NULL,
    prescription TEXT NOT NULL,
    clinical_notes TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    scheduled_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'SCHEDULED' CHECK (status IN ('SCHEDULED', 'COMPLETED', 'CANCELLED')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def get_connection() -> sqlite3.Connection:
    target_path = str(settings.db_path)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)

    conns: dict[str, sqlite3.Connection] | None = getattr(_thread_local, "conns", None)
    if conns is None:
        conns = {}
        _thread_local.conns = conns
        with _init_lock:
            _all_conn_maps.append(conns)

    conn = conns.get(target_path)
    if conn is None:
        conn = sqlite3.connect(target_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conns[target_path] = conn

    if target_path not in _initialized_paths:
        with _init_lock:
            if target_path not in _initialized_paths:
                conn.executescript(SCHEMA_SQL)
                existing_cols = {
                    row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
                }
                if "mfa_pending_secret_enc" not in existing_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN mfa_pending_secret_enc TEXT;")
                if "mfa_last_used_step" not in existing_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN mfa_last_used_step INTEGER;")
                conn.commit()
                _initialized_paths.add(target_path)

    return conn


def close_thread_connections() -> None:
    with _init_lock:
        for conn_map in _all_conn_maps:
            for conn in list(conn_map.values()):
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
            conn_map.clear()
        _initialized_paths.clear()


def query_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    row = get_connection().execute(sql, params).fetchone()
    return dict(row) if row is not None else None


def query_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    rows = get_connection().execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def execute_write(sql: str, params: tuple[Any, ...] = ()) -> int:
    with _write_lock:
        conn = get_connection()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid or 0


def execute_transaction(statements: list[tuple[str, tuple[Any, ...]]]) -> None:
    with _write_lock:
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for sql, params in statements:
                conn.execute(sql, params)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

