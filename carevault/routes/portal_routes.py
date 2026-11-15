"""
Insecure Server-Side Rendered (SSR) Portal Routes (carevault/routes/portal_routes.py)
INTENTIONALLY VULNERABLE BASELINE:
- No CSRF token validation on forms
- Reflected and Stored XSS rendered using raw HTML
- IDOR on clinical records retrieval
- SQL Injection in search and authentication forms
"""
from __future__ import annotations

import secrets
from typing import Any
from flask import (
    Blueprint,
    Response,
    make_response,
    redirect,
    render_template,
    request,
    jsonify,
)

from carevault.database import (
    raw_query_all,
    raw_query_one,
    raw_execute_write,
    weak_md5_hash,
)
from carevault.seed import DEMO_ACCOUNTS

portal_bp = Blueprint("portal", __name__)


def _get_portal_user() -> dict[str, Any] | None:
    session_id = request.cookies.get("cv_insecure_session")
    if not session_id:
        return None
    try:
        session = raw_query_one(f"SELECT * FROM sessions WHERE session_id = '{session_id}'")
        if not session:
            return None
        return raw_query_one(f"SELECT * FROM users WHERE id = {session['user_id']}")
    except Exception:
        return None


@portal_bp.get("/")
def index() -> str:
    user = _get_portal_user()
    active_tab = request.args.get("tab", "records")
    demo_key = request.args.get("demo", "")
    alert_msg = request.args.get("msg", "")
    alert_kind = request.args.get("kind", "info")

    login_email = ""
    login_pwd = ""
    if request.args.get("demo_sqli"):
        login_email = "' OR '1'='1' --"
        login_pwd = "any_password"
        user = None
    elif demo_key and demo_key in [a["email"].split("@")[0] for a in DEMO_ACCOUNTS]:
        for a in DEMO_ACCOUNTS:
            if a["email"].startswith(demo_key):
                login_email = a["email"]
                login_pwd = a["password"]
                user = None
                break

    # If demo is admin or doctor
    demo_chips = {
        "admin": ("admin@carevault.local", "Admin@CareVault#2026!", "Admin (System)"),
        "dr.aisyah": ("dr.aisyah@carevault.local", "DrAisyah@Clinic#2026!", "Doctor (Dr. Aisyah)"),
        "reception": ("reception@carevault.local", "FrontDesk@Staff#2026!", "Staff (Siti)"),
        "amira.patient": ("amira.patient@carevault.local", "Amira@Patient#2026!", "Patient (Amira - ID #5)"),
        "daniel.patient": ("daniel.patient@carevault.local", "Daniel@Patient#2026!", "Patient (Daniel - ID #6)"),
    }

    records: list[dict[str, Any]] = []
    appointments: list[dict[str, Any]] = []
    all_users: list[dict[str, Any]] = []
    all_patients: list[dict[str, Any]] = []
    single_record: dict[str, Any] | None = None
    search_query = request.args.get("q", "")

    # VULNERABILITY: IDOR on single record view (Accessible regardless of authentication/authorization!)
    view_rec_id = request.args.get("record_id")
    if view_rec_id:
        try:
            # Fetches ANY record directly by ID without checking if patient owns it or if doctor is assigned!
            single_record = raw_query_one(
                f"SELECT r.*, p.full_name as patient_name, d.full_name as doctor_name "
                f"FROM clinical_records r "
                f"JOIN users p ON r.patient_id = p.id "
                f"JOIN users d ON r.doctor_id = d.id "
                f"WHERE r.id = '{view_rec_id}'"
            )
        except Exception:
            single_record = None

    if user:
        all_patients = raw_query_all("SELECT id, full_name, email FROM users WHERE role = 'patient'")

        if search_query:
            # VULNERABILITY: SQL Injection in search query
            sql = f"SELECT r.*, p.full_name as patient_name, d.full_name as doctor_name FROM clinical_records r JOIN users p ON r.patient_id = p.id JOIN users d ON r.doctor_id = d.id WHERE r.diagnosis LIKE '%{search_query}%' OR r.clinical_notes LIKE '%{search_query}%'"
            try:
                records = raw_query_all(sql)
            except Exception as e:
                alert_msg = f"SQL Syntax Error triggered: {str(e)}"
                alert_kind = "error"
        else:
            # VULNERABILITY: Permissive display of records
            records = raw_query_all("SELECT r.*, p.full_name as patient_name, d.full_name as doctor_name FROM clinical_records r JOIN users p ON r.patient_id = p.id JOIN users d ON r.doctor_id = d.id ORDER BY r.id ASC")

        appointments = raw_query_all("SELECT a.*, p.full_name as patient_name, d.full_name as doctor_name FROM appointments a JOIN users p ON a.patient_id = p.id JOIN users d ON a.doctor_id = d.id ORDER BY a.scheduled_at ASC")

        if user["role"] == "admin":
            all_users = raw_query_all("SELECT * FROM users ORDER BY id ASC")

    return render_template(
        "index.html",
        user=user,
        active_tab=active_tab,
        demo_accounts=demo_chips,
        selected_demo=demo_key,
        login_email=login_email,
        login_password=login_pwd,
        alert_message=alert_msg,
        alert_kind=alert_kind,
        records=records,
        appointments=appointments,
        all_patients=all_patients,
        all_users=all_users,
        single_record=single_record,
        search_query=search_query,
    )


@portal_bp.post("/portal/login")
def portal_login() -> Response:
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    # VULNERABILITY: SQL Injection!
    # If the user enters `' OR '1'='1' --` in email, the WHERE clause evaluates to TRUE!
    pwd_hash = weak_md5_hash(password)
    sql = f"SELECT * FROM users WHERE email = '{email}' AND password_hash = '{pwd_hash}'"

    user = None
    try:
        user = raw_query_one(sql)
    except Exception as e:
        return redirect(f"/?msg=SQL+Error:+{str(e)}&kind=error")

    if not user:
        # VULNERABILITY: Account enumeration timing / message leak
        check_user = raw_query_one(f"SELECT * FROM users WHERE email = '{email}'")
        if not check_user and "' OR '" not in email:
            return redirect("/?msg=Error:+Email+address+does+not+exist!&kind=error")
        return redirect("/?msg=Error:+Incorrect+password!&kind=error")

    session_id = secrets.token_hex(16)
    raw_execute_write(f"INSERT INTO sessions (session_id, user_id) VALUES ('{session_id}', {user['id']})")

    resp = make_response(redirect("/?tab=records&msg=Authenticated+Successfully+(Insecure+Mode)&kind=success"))
    # VULNERABILITY: Insecure cookie without HttpOnly or Secure flags!
    resp.set_cookie("cv_insecure_session", session_id, path="/", httponly=False, secure=False)
    return resp


@portal_bp.post("/portal/register")
def portal_register() -> Response:
    full_name = request.form.get("fullName", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "")

    # VULNERABILITY: Mass Assignment!
    # If an attacker includes an HTML input or intercepted field role="admin", it gets accepted!
    role = request.form.get("role", "patient")

    if not email or not password:
        return redirect("/?msg=Error:+Email+and+password+required&kind=error")

    existing = raw_query_one(f"SELECT * FROM users WHERE email = '{email}'")
    if existing:
        return redirect("/?msg=Error:+Email+already+registered&kind=error")

    pwd_hash = weak_md5_hash(password)
    raw_execute_write(
        f"INSERT INTO users (full_name, email, phone, password_hash, role) "
        f"VALUES ('{full_name}', '{email}', '{phone}', '{pwd_hash}', '{role}')"
    )
    return redirect(f"/?msg=Registration+successful+with+role+{role}!+Please+sign+in.&kind=success")


@portal_bp.post("/portal/records/create")
def portal_create_record() -> Response:
    user = _get_portal_user()
    if not user:
        return redirect("/?msg=Please+login+first&kind=error")

    # VULNERABILITY: Missing CSRF token check!
    patient_id = request.form.get("patientId")
    diagnosis = request.form.get("diagnosis", "")
    prescription = request.form.get("prescription", "")
    clinical_notes = request.form.get("clinicalNotes", "")
    severity = request.form.get("severity", "LOW")

    try:
        # VULNERABILITY: Stored XSS - Inserts raw unencoded script/HTML tags into SQLite!
        raw_execute_write(
            f"INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity) "
            f"VALUES ({patient_id}, {user['id']}, '{diagnosis}', '{prescription}', '{clinical_notes}', '{severity}')"
        )
        return redirect("/?tab=records&msg=Clinical+record+added+(Unsanitized)&kind=success")
    except Exception as e:
        return redirect(f"/?tab=records&msg=Database+Syntax+Error:+{str(e)}&kind=error")


@portal_bp.post("/portal/appointments/create")
def portal_create_appointment() -> Response:
    user = _get_portal_user()
    if not user:
        return redirect("/?msg=Please+login+first&kind=error")

    # VULNERABILITY: Missing CSRF token check!
    patient_id = request.form.get("patientId") or user["id"]
    doctor_id = request.form.get("doctorId") or 2
    scheduled_at = request.form.get("scheduledAt", "")
    reason = request.form.get("reason", "")

    try:
        raw_execute_write(
            f"INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status) "
            f"VALUES ({patient_id}, {doctor_id}, '{scheduled_at}', '{reason}', 'SCHEDULED')"
        )
        return redirect("/?tab=appointments&msg=Appointment+booked&kind=success")
    except Exception as e:
        return redirect(f"/?tab=appointments&msg=Database+Syntax+Error:+{str(e)}&kind=error")


@portal_bp.post("/portal/admin/update-role")
def portal_update_role() -> Response:
    user = _get_portal_user()
    if not user or user["role"] != "admin":
        return redirect("/?msg=Unauthorized&kind=error")

    # VULNERABILITY: Missing CSRF token check!
    target_id = request.form.get("userId")
    new_role = request.form.get("newRole", "patient")
    try:
        raw_execute_write(f"UPDATE users SET role = '{new_role}' WHERE id = {target_id}")
        return redirect(f"/?tab=admin&msg=User+{target_id}+role+changed+to+{new_role}&kind=success")
    except Exception as e:
        return redirect(f"/?tab=admin&msg=Database+Syntax+Error:+{str(e)}&kind=error")


@portal_bp.post("/portal/logout")
def portal_logout() -> Response:
    session_id = request.cookies.get("cv_insecure_session")
    if session_id:
        raw_execute_write(f"DELETE FROM sessions WHERE session_id = '{session_id}'")
    resp = make_response(redirect("/?msg=Signed+out&kind=info"))
    resp.delete_cookie("cv_insecure_session")
    return resp


@portal_bp.get("/crash")
def trigger_crash() -> Response:
    """VULNERABILITY: Triggers an unhandled exception to leak full Python stack trace and local variables."""
    secret_key = "INTERNAL_SERVER_DB_ENCRYPTION_KEY_SECRET_999"
    division_by_zero = 1 / 0
    return jsonify({"result": division_by_zero, "secret": secret_key})

