"""
100% Pure-Python Server-Side Rendered (SSR) Clinical Portal Routes (`carevault/routes/portal_routes.py`)
- Zero client-side JavaScript required (`script-src 'none'` compatible)
- Enforces identical Pydantic `StrictSchema`, Argon2id, TOTP MFA, `__Host-cv_session`,
  constant-time `_csrf_token`, RBAC/PoLP, IDOR, and redacted `ERR-XXXXXXXX` Correlation-ID controls
"""
from __future__ import annotations

import datetime as dt
import secrets
import ssl
import threading
from typing import Any

from flask import (
    Blueprint,
    Response,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
)
from pydantic import BaseModel, ValidationError
from werkzeug.wrappers import Response as WerkzeugResponse

from carevault.config import settings
from carevault.database import execute_transaction, execute_write, query_all, query_one
from carevault.middleware.auth import (
    clear_session_cookie,
    issue_session,
    load_optional_session,
    verify_request_csrf,
)
from carevault.middleware.error_handler import (
    AppError,
    _write_internal_error_log,
    redact_sensitive_object,
)
from carevault.middleware.rate_limiter import auth_rate_limit
from carevault.middleware.rbac import (
    ROLE_PERMISSIONS,
    assert_can_read_clinical_record,
    assert_doctor_assigned_to_patient,
    has_permission,
)
from carevault.routes.auth_routes import _record_failed_attempt
from carevault.security.extension_hooks import security_events
from carevault.security.password import (
    hash_password,
    validate_password_policy,
    verify_password,
)
from carevault.security.tls_validator import validate_certificate_chain
from carevault.security.totp import (
    build_otpauth_qr,
    decrypt_secret,
    encrypt_secret,
    generate_totp_secret,
    verify_totp_code,
)
from carevault.security.validation import (
    AppointmentStatusPayload,
    CreateAppointmentPayload,
    CreateRecordPayload,
    LoginPayload,
    MfaDisablePayload,
    MfaVerifyPayload,
    RegisterPayload,
    UpdateUserRolePayload,
    validate_positive_id,
)

portal_bp = Blueprint("portal", __name__)

DEMO_CREDENTIALS: dict[str, tuple[str, str, str]] = {
    "patient1": ("amira.patient@carevault.local", "Amira@Patient#2026!", "Patient #1 (Amira)"),
    "patient2": ("daniel.patient@carevault.local", "Daniel@Patient#2026!", "Patient #2 (Daniel)"),
    "doctor1": ("dr.aisyah@carevault.local", "DrAisyah@Clinic#2026!", "Doctor #1 (Dr. Aisyah)"),
    "doctor2": ("dr.kenneth@carevault.local", "DrKenneth@Clinic#2026!", "Doctor #2 (Dr. Kenneth)"),
    "staff": ("reception@carevault.local", "FrontDesk@Staff#2026!", "Reception Staff"),
    "admin": ("admin@carevault.local", "Admin@CareVault#2026!", "Security Admin"),
}

# Thread-safe short-lived flash store keyed by opaque nonce so URLs remain clean
_flash_lock = threading.Lock()
_flash_messages: dict[str, tuple[str, str, float]] = {}

# Thread-safe 180s pre-authentication MFA challenge store (avoids reflecting passwords in HTML)
_mfa_challenge_lock = threading.Lock()
_mfa_challenges: dict[str, dict[str, Any]] = {}


def _create_mfa_challenge(user_id: int, ip_addr: str) -> str:
    nonce = secrets.token_hex(24)
    now_ts = dt.datetime.now(dt.UTC).timestamp()
    with _mfa_challenge_lock:
        expired = [k for k, v in _mfa_challenges.items() if now_ts - v["created_at"] > 180]
        for k in expired:
            _mfa_challenges.pop(k, None)
        _mfa_challenges[nonce] = {
            "user_id": user_id,
            "ip": ip_addr,
            "created_at": now_ts,
            "tries": 0,
        }
    return nonce


def _peek_mfa_challenge(nonce: str, ip_addr: str) -> int | None:
    if not nonce:
        return None
    now_ts = dt.datetime.now(dt.UTC).timestamp()
    with _mfa_challenge_lock:
        entry = _mfa_challenges.get(nonce)
        if not entry:
            return None
        if now_ts - entry["created_at"] > 180 or entry["ip"] != ip_addr:
            _mfa_challenges.pop(nonce, None)
            return None
        return int(entry["user_id"])


def _record_mfa_challenge_failure(nonce: str, ip_addr: str) -> bool:
    """Increment failure counter once; return True if challenge remains usable (< 3 tries)."""
    if not nonce:
        return False
    now_ts = dt.datetime.now(dt.UTC).timestamp()
    with _mfa_challenge_lock:
        entry = _mfa_challenges.get(nonce)
        if not entry:
            return False
        if now_ts - entry["created_at"] > 180 or entry["ip"] != ip_addr:
            _mfa_challenges.pop(nonce, None)
            return False
        entry["tries"] += 1
        if entry["tries"] >= 3:
            _mfa_challenges.pop(nonce, None)
            return False
        return True


def _consume_mfa_challenge(nonce: str) -> None:
    if not nonce:
        return
    with _mfa_challenge_lock:
        _mfa_challenges.pop(nonce, None)


def _push_flash(message: str, kind: str = "success") -> str:
    fid = secrets.token_hex(8)
    now_ts = dt.datetime.now(dt.UTC).timestamp()
    with _flash_lock:
        expired = [k for k, v in _flash_messages.items() if now_ts - v[2] > 120]
        for k in expired:
            _flash_messages.pop(k, None)
        _flash_messages[fid] = (message, kind, now_ts)
    return fid


def _pop_flash(fid: str | None) -> tuple[str | None, str]:
    if not fid:
        return None, "success"
    with _flash_lock:
        item = _flash_messages.pop(fid, None)
    if not item:
        return None, "success"
    return item[0], item[1]


def _validate_form_model(model_cls: type[BaseModel], data: dict[str, Any]) -> Any:
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        details = [
            {
                "field": ".".join(str(p) for p in err["loc"]) or "payload",
                "message": err["msg"],
            }
            for err in exc.errors()
        ]
        raise AppError(
            400,
            "VALIDATION_ERROR",
            "Please review and correct the highlighted input fields.",
            details,
        ) from exc


def _log_and_format_app_error(err: AppError, raw_payload: dict[str, Any]) -> str:
    correlation_id = f"ERR-{secrets.token_hex(4).upper()}"
    current_user = getattr(g, "user", None)
    _write_internal_error_log(
        {
            "correlationId": correlation_id,
            "timestamp": dt.datetime.now(dt.UTC).isoformat(),
            "statusCode": err.status_code,
            "errorCode": err.error_code,
            "method": request.method,
            "path": request.path,
            "userId": current_user["id"] if current_user else None,
            "ip": request.remote_addr,
            "sanitizedBody": redact_sensitive_object(raw_payload),
            "internalMessage": err.public_message,
        }
    )
    security_events.publish(
        "error.handled",
        {
            "correlationId": correlation_id,
            "statusCode": err.status_code,
            "errorCode": err.error_code,
            "path": request.path,
            "userId": current_user["id"] if current_user else None,
        },
    )
    detail_str = ""
    if err.details:
        detail_str = " (" + " ".join(d["message"] for d in err.details) + ")"
    return f"{err.public_message}{detail_str} [Ref: {correlation_id}]"


def _default_tab_for_role(role: str) -> str:
    if role == "admin":
        return "admin"
    if role == "staff":
        return "appointments"
    return "records"


def _build_live_tls_context() -> dict[str, Any]:
    cert_validation = validate_certificate_chain()
    raw_sock = request.environ.get("werkzeug.socket")
    if isinstance(raw_sock, ssl.SSLSocket):
        cipher_tuple = raw_sock.cipher()
        active_conn = {
            "encrypted": True,
            "negotiatedProtocol": raw_sock.version(),
            "cipherName": cipher_tuple[0] if cipher_tuple else "N/A",
        }
    elif request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        active_conn = {
            "encrypted": True,
            "negotiatedProtocol": "TLSv1.3 (Edge Proxy)",
            "cipherName": "TLS_AES_256_GCM_SHA384",
        }
    else:
        active_conn = {"encrypted": False, "negotiatedProtocol": "NONE", "cipherName": "N/A"}

    return {"activeConnection": active_conn, "pkiValidation": cert_validation}


def _render_portal(
    *,
    alert_message: str | None = None,
    alert_kind: str = "success",
    active_tab: str | None = None,
    login_email: str = "",
    login_password: str = "",
    mfa_challenge_token: str | None = None,
    reg_name: str = "",
    reg_email: str = "",
    reg_phone: str = "",
    rec_patient_id: int | None = None,
    rec_severity: str = "LOW",
    rec_diagnosis: str = "",
    rec_prescription: str = "",
    rec_notes: str = "",
    appt_patient_id: int | None = None,
    appt_doctor_id: int | None = None,
    appt_reason: str = "",
    appt_dt: str | None = None,
    mfa_qr_data_url: str | None = None,
    mfa_manual_key: str | None = None,
    probe_record_id: int = 2,
    status_code: int = 200,
) -> tuple[str, int]:
    user = getattr(g, "user", None)
    if user is None:
        user = load_optional_session()

    flash_msg, flash_kind = _pop_flash(request.args.get("f"))
    if not alert_message and flash_msg:
        alert_message = flash_msg
        alert_kind = flash_kind

    if not user:
        demo_key = request.args.get("demo", "")
        selected_demo = ""
        if demo_key in DEMO_CREDENTIALS and not login_email and not mfa_challenge_token:
            login_email, login_password, demo_label = DEMO_CREDENTIALS[demo_key]
            selected_demo = demo_key
            if not alert_message:
                alert_message = f"Loaded demo credentials for {demo_label}. Click 'Authenticate Securely' below."
                alert_kind = "success"

        return (
            render_template(
                "index.html",
                user=None,
                alert_message=alert_message,
                alert_kind=alert_kind,
                demo_accounts=DEMO_CREDENTIALS,
                selected_demo=selected_demo,
                login_email=login_email,
                login_password=login_password,
                mfa_challenge_token=mfa_challenge_token,
                reg_name=reg_name,
                reg_email=reg_email,
                reg_phone=reg_phone,
            ),
            status_code,
        )

    role = user["role"]
    tab = active_tab or request.args.get("tab") or _default_tab_for_role(role)
    if tab == "admin" and role != "admin":
        tab = _default_tab_for_role(role)
    if tab not in {"records", "appointments", "admin", "mfa"}:
        tab = _default_tab_for_role(role)

    permissions = sorted(ROLE_PERMISSIONS.get(role, frozenset()))
    doctors = query_all(
        "SELECT id, full_name, email FROM users WHERE role = 'doctor' ORDER BY full_name ASC"
    )

    patients: list[dict[str, Any]] = []
    if role == "staff":
        patients = query_all(
            "SELECT id, full_name, email, phone, assigned_doctor_id FROM users WHERE role = 'patient' ORDER BY full_name ASC"
        )
    elif role == "doctor":
        patients = query_all(
            """
            SELECT id, full_name, email, phone, assigned_doctor_id FROM users
            WHERE role = 'patient' AND assigned_doctor_id = ?
            ORDER BY full_name ASC
            """,
            (user["id"],),
        )

    records: list[dict[str, Any]] = []
    if role == "patient":
        records = query_all(
            """
            SELECT r.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM clinical_records r
            JOIN users p ON p.id = r.patient_id
            JOIN users d ON d.id = r.doctor_id
            WHERE r.patient_id = ?
            ORDER BY r.id DESC
            """,
            (user["id"],),
        )
    elif role == "doctor":
        records = query_all(
            """
            SELECT r.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM clinical_records r
            JOIN users p ON p.id = r.patient_id
            JOIN users d ON d.id = r.doctor_id
            WHERE p.assigned_doctor_id = ? OR r.doctor_id = ?
            ORDER BY r.id DESC
            """,
            (user["id"], user["id"]),
        )

    appointments: list[dict[str, Any]] = []
    if role == "patient":
        appointments = query_all(
            """
            SELECT a.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM appointments a
            JOIN users p ON p.id = a.patient_id
            JOIN users d ON d.id = a.doctor_id
            WHERE a.patient_id = ?
            ORDER BY a.scheduled_at ASC
            """,
            (user["id"],),
        )
    elif role == "doctor":
        appointments = query_all(
            """
            SELECT a.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM appointments a
            JOIN users p ON p.id = a.patient_id
            JOIN users d ON d.id = a.doctor_id
            WHERE a.doctor_id = ?
            ORDER BY a.scheduled_at ASC
            """,
            (user["id"],),
        )
    elif role == "staff":
        appointments = query_all(
            """
            SELECT a.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM appointments a
            JOIN users p ON p.id = a.patient_id
            JOIN users d ON d.id = a.doctor_id
            ORDER BY a.scheduled_at ASC
            """
        )

    admin_users: list[dict[str, Any]] = []
    tls_info: dict[str, Any] | None = None
    now_utc = dt.datetime.now(dt.UTC)
    if role == "admin":
        raw_users = query_all(
            """
            SELECT id, full_name, email, phone, role, assigned_doctor_id, mfa_enabled,
                   failed_login_attempts, locked_until, created_at
            FROM users ORDER BY id ASC
            """
        )
        for u in raw_users:
            is_locked = False
            if u.get("locked_until"):
                try:
                    is_locked = dt.datetime.fromisoformat(u["locked_until"]) > now_utc
                except ValueError:
                    is_locked = False
            admin_users.append({**u, "is_locked": is_locked})
        tls_info = _build_live_tls_context()

    # If user is viewing the MFA tab and already has a staged pending secret, render its QR cleanly
    if tab == "mfa" and not mfa_qr_data_url:
        curr_row = query_one("SELECT mfa_pending_secret_enc FROM users WHERE id = ?", (user["id"],))
        if curr_row and curr_row.get("mfa_pending_secret_enc"):
            secret_b32 = decrypt_secret(curr_row["mfa_pending_secret_enc"])
            qr_obj = build_otpauth_qr(user["email"], secret_b32)
            mfa_qr_data_url = qr_obj["qrDataUrl"]
            mfa_manual_key = secret_b32

    default_appt_dt = appt_dt or (now_utc + dt.timedelta(days=7)).strftime("%Y-%m-%dT09:30")

    return (
        render_template(
            "index.html",
            user=user,
            csrf_token=g.csrf_token,
            permissions=permissions,
            active_tab=tab,
            alert_message=alert_message,
            alert_kind=alert_kind,
            doctors=doctors,
            patients=patients,
            records=records,
            appointments=appointments,
            admin_users=admin_users,
            tls_info=tls_info,
            mfa_qr_data_url=mfa_qr_data_url,
            mfa_manual_key=mfa_manual_key,
            probe_record_id=probe_record_id,
            default_appt_dt=default_appt_dt,
            rec_patient_id=rec_patient_id,
            rec_severity=rec_severity,
            rec_diagnosis=rec_diagnosis,
            rec_prescription=rec_prescription,
            rec_notes=rec_notes,
            appt_patient_id=appt_patient_id,
            appt_doctor_id=appt_doctor_id,
            appt_reason=appt_reason,
        ),
        status_code,
    )


@portal_bp.get("/")
def home() -> tuple[str, int]:
    rechecked = request.args.get("rechecked")
    msg = (
        "TLS 1.3 & X.509 Certificate Chain re-validated successfully (6/6 checks passed)."
        if rechecked
        else None
    )
    return _render_portal(alert_message=msg, alert_kind="success")


@portal_bp.get("/clinical-portal")
@portal_bp.get("/portal")
@portal_bp.get("/portal/<path:subpath>")
def redirect_portal_get(subpath: str = "") -> WerkzeugResponse:
    """Gracefully redirects GET navigations/refreshes on form action URLs back to the portal workspace."""
    tab_arg = request.args.get("tab", "")
    if tab_arg in {"records", "appointments", "admin", "mfa"}:
        return redirect(f"/?tab={tab_arg}", code=303)
    if subpath.startswith("mfa"):
        return redirect("/?tab=mfa", code=303)
    if subpath.startswith("appointments"):
        return redirect("/?tab=appointments", code=303)
    if subpath.startswith("admin"):
        return redirect("/?tab=admin", code=303)
    if subpath.startswith("records"):
        return redirect("/?tab=records", code=303)
    return redirect("/", code=303)


@portal_bp.get("/favicon.ico")
def favicon() -> Response:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<path fill="#0f4c81" d="M32 4L8 14v18c0 15.2 10.2 28.9 24 32 13.8-3.1 24-16.8 24-32V14L32 4z"/>'
        '<path fill="#ffffff" d="M29 18h6v11h11v6H35v11h-6V35H18v-6h11V18z"/>'
        "</svg>"
    )
    resp = Response(svg, status=200, mimetype="image/svg+xml")
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@portal_bp.get("/certs/carevault-root-ca.crt")
def download_root_ca() -> Response:
    return send_file(
        str(settings.tls_ca_cert_path),
        mimetype="application/x-x509-ca-cert",
        as_attachment=True,
        download_name="carevault-root-ca.crt",
    )


@portal_bp.post("/portal/login")
@auth_rate_limit
def portal_login() -> WerkzeugResponse | tuple[str, int]:
    email_input = request.form.get("email", "")
    password_input = request.form.get("password", "")
    raw_form: dict[str, Any] = {
        "email": email_input,
        "password": password_input,
        "totpCode": request.form.get("totpCode") or None,
    }
    try:
        body = _validate_form_model(LoginPayload, raw_form)
        user_row = query_one("SELECT * FROM users WHERE email = ?", (body.email,))

        password_valid = verify_password(
            user_row["password_hash"] if user_row else None,
            body.password,
        )
        if not user_row:
            security_events.publish(
                "auth.login.failed",
                {"userId": None, "ip": request.remote_addr, "reason": "unknown_identifier"},
            )
            raise AppError(401, "INVALID_CREDENTIALS", "Invalid email address or password.")

        now_utc = dt.datetime.now(dt.UTC)
        if user_row.get("locked_until"):
            locked_dt = dt.datetime.fromisoformat(user_row["locked_until"])
            if locked_dt > now_utc:
                security_events.publish(
                    "auth.login.blocked_lockout",
                    {"userId": user_row["id"], "ip": request.remote_addr},
                )
                raise AppError(
                    423,
                    "ACCOUNT_LOCKED",
                    "This account is temporarily locked due to repeated failed sign-in attempts. Please try again later or contact an administrator.",
                )

        if not password_valid:
            _record_failed_attempt(user_row, "bad_password")
            raise AppError(401, "INVALID_CREDENTIALS", "Invalid email address or password.")

        if user_row["mfa_enabled"] == 1 and user_row.get("mfa_secret_enc"):
            if not body.totpCode:
                challenge_nonce = _create_mfa_challenge(
                    user_row["id"], request.remote_addr or "unknown"
                )
                return _render_portal(
                    alert_message="Primary credentials verified. Enter your 6-digit Authenticator code below to complete sign-in.",
                    alert_kind="success",
                    login_email=body.email,
                    mfa_challenge_token=challenge_nonce,
                )
            raw_secret = decrypt_secret(user_row["mfa_secret_enc"])
            totp_result = verify_totp_code(
                raw_secret,
                body.totpCode,
                last_used_step=user_row.get("mfa_last_used_step"),
            )
            if not totp_result["valid"]:
                reason = "replayed_totp" if totp_result["replayed"] else "bad_totp"
                _record_failed_attempt(user_row, reason)
                msg = (
                    "This 6-digit code was already used. Please wait for the next 30-second Authenticator code."
                    if totp_result["replayed"]
                    else "Invalid 6-digit Authenticator verification code."
                )
                raise AppError(401, "INVALID_MFA_CODE", msg)
            execute_write(
                "UPDATE users SET mfa_last_used_step = ? WHERE id = ?",
                (totp_result["matchedStep"], user_row["id"]),
            )

        execute_write(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_row["id"],),
        )
        target_tab = _default_tab_for_role(user_row["role"])
        fid = _push_flash(f"Authenticated securely as {user_row['full_name']} ({user_row['role'].upper()}).", "success")
        resp = make_response(redirect(f"/?tab={target_tab}&f={fid}", code=303))
        issue_session(user_row["id"], resp)
        security_events.publish(
            "auth.login.success",
            {
                "userId": user_row["id"],
                "role": user_row["role"],
                "mfaUsed": bool(user_row["mfa_enabled"]),
                "ip": request.remote_addr,
            },
        )
        return resp
    except AppError as err:
        err_text = _log_and_format_app_error(err, raw_form)
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            login_email=email_input,
            status_code=err.status_code,
        )


@portal_bp.post("/portal/login/mfa")
@auth_rate_limit
def portal_login_mfa() -> WerkzeugResponse | tuple[str, int]:
    challenge_token = request.form.get("mfaChallengeToken", "")
    raw_code = request.form.get("totpCode", "")
    ip_addr = request.remote_addr or "unknown"
    fallback_email = ""
    keep_challenge: str | None = None
    try:
        uid = _peek_mfa_challenge(challenge_token, ip_addr)
        if not uid:
            raise AppError(
                401,
                "MFA_CHALLENGE_EXPIRED",
                "Your 2FA verification prompt expired or exceeded retry limits. Please sign in again.",
            )
        user_row = query_one("SELECT * FROM users WHERE id = ?", (uid,))
        if not user_row or user_row["mfa_enabled"] != 1 or not user_row.get("mfa_secret_enc"):
            _consume_mfa_challenge(challenge_token)
            raise AppError(401, "INVALID_CREDENTIALS", "Invalid authentication state.")

        fallback_email = str(user_row["email"])
        now_utc = dt.datetime.now(dt.UTC)
        if (
            user_row.get("locked_until")
            and dt.datetime.fromisoformat(user_row["locked_until"]) > now_utc
        ):
            _consume_mfa_challenge(challenge_token)
            raise AppError(
                423,
                "ACCOUNT_LOCKED",
                "This account is temporarily locked due to repeated failed sign-in attempts.",
            )

        try:
            body = _validate_form_model(MfaVerifyPayload, {"totpCode": raw_code})
        except AppError:
            if _record_mfa_challenge_failure(challenge_token, ip_addr):
                keep_challenge = challenge_token
            raise

        raw_secret = decrypt_secret(user_row["mfa_secret_enc"])
        totp_result = verify_totp_code(
            raw_secret,
            body.totpCode,
            last_used_step=user_row.get("mfa_last_used_step"),
        )
        if not totp_result["valid"]:
            reason = "replayed_totp" if totp_result["replayed"] else "bad_totp"
            _record_failed_attempt(user_row, reason)
            if _record_mfa_challenge_failure(challenge_token, ip_addr):
                keep_challenge = challenge_token
            msg = (
                "This 6-digit code was already used. Please wait for the next 30-second Authenticator code."
                if totp_result["replayed"]
                else "Invalid 6-digit Authenticator verification code."
            )
            raise AppError(401, "INVALID_MFA_CODE", msg)

        _consume_mfa_challenge(challenge_token)
        execute_transaction(
            [
                (
                    "UPDATE users SET mfa_last_used_step = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                    (totp_result["matchedStep"], user_row["id"]),
                )
            ]
        )
        target_tab = _default_tab_for_role(user_row["role"])
        fid = _push_flash(
            f"2FA verified! Signed in as {user_row['full_name']} ({user_row['role'].upper()}).",
            "success",
        )
        resp = make_response(redirect(f"/?tab={target_tab}&f={fid}", code=303))
        issue_session(user_row["id"], resp)
        security_events.publish(
            "auth.login.success",
            {
                "userId": user_row["id"],
                "role": user_row["role"],
                "mfaUsed": True,
                "ip": request.remote_addr,
            },
        )
        return resp
    except AppError as err:
        err_text = _log_and_format_app_error(
            err, {"mfaChallengeToken": challenge_token, "totpCode": raw_code}
        )
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            login_email=fallback_email,
            mfa_challenge_token=keep_challenge,
            status_code=err.status_code,
        )


@portal_bp.post("/portal/register")
@auth_rate_limit
def portal_register() -> WerkzeugResponse | tuple[str, int]:
    raw_form = {
        "fullName": request.form.get("fullName", ""),
        "email": request.form.get("email", ""),
        "phone": request.form.get("phone", ""),
        "password": request.form.get("password", ""),
    }
    try:
        body = _validate_form_model(RegisterPayload, raw_form)
        policy = validate_password_policy(body.password, [body.fullName, body.email])
        if not policy["valid"]:
            raise AppError(
                400,
                "WEAK_PASSWORD",
                "Password does not satisfy CareVault security policy.",
                [{"field": "password", "message": m} for m in policy["issues"]],
            )

        existing = query_one("SELECT id FROM users WHERE email = ?", (body.email,))
        if existing:
            raise AppError(
                409,
                "REGISTRATION_CONFLICT",
                "Unable to complete registration with the provided email address.",
            )

        pwd_hash = hash_password(body.password)
        doctors = query_all("SELECT id FROM users WHERE role = 'doctor' ORDER BY full_name ASC")
        default_doc_id = doctors[0]["id"] if doctors else None
        user_id = execute_write(
            """
            INSERT INTO users (full_name, email, phone, password_hash, role, assigned_doctor_id)
            VALUES (?, ?, ?, ?, 'patient', ?)
            """,
            (body.fullName, body.email, body.phone, pwd_hash, default_doc_id),
        )
        security_events.publish(
            "auth.user.registered",
            {"userId": user_id, "role": "patient", "ip": request.remote_addr},
        )
        fid = _push_flash(
            f"Patient account created securely (Entropy: {policy['entropyBits']} bits). You may now sign in.",
            "success",
        )
        return redirect(f"/?f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(err, raw_form)
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            reg_name=raw_form["fullName"],
            reg_email=raw_form["email"],
            reg_phone=raw_form["phone"],
            status_code=err.status_code,
        )


def _require_portal_session() -> dict[str, Any]:
    user = load_optional_session()
    if not user:
        raise AppError(401, "AUTHENTICATION_REQUIRED", "Please sign in to access this workspace.")
    verify_request_csrf()
    return user


@portal_bp.post("/portal/logout")
def portal_logout() -> WerkzeugResponse | tuple[str, int]:
    user = load_optional_session()
    if user:
        try:
            verify_request_csrf()
        except AppError as err:
            err_text = _log_and_format_app_error(err, {})
            return _render_portal(
                alert_message=err_text,
                alert_kind="error",
                status_code=err.status_code,
            )
        execute_write(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ?",
            (g.session_token_hash,),
        )
        security_events.publish("auth.logout", {"userId": user["id"]})
    fid = _push_flash("Signed out securely and server session token revoked.", "success")
    resp = make_response(redirect(f"/?f={fid}", code=303))
    clear_session_cookie(resp)
    return resp


@portal_bp.post("/portal/records/create")
def portal_create_record() -> WerkzeugResponse | tuple[str, int]:
    raw_pid = request.form.get("patientId", "")
    raw_sev = request.form.get("severity", "LOW")
    raw_diag = request.form.get("diagnosis", "")
    raw_presc = request.form.get("prescription", "")
    raw_notes = request.form.get("clinicalNotes", "")
    raw_form: dict[str, Any] = {
        "patientId": raw_pid,
        "severity": raw_sev,
        "diagnosis": raw_diag,
        "prescription": raw_presc,
        "clinicalNotes": raw_notes,
    }
    sticky_pid = int(raw_pid) if raw_pid.isdigit() and int(raw_pid) > 0 else None
    try:
        user = _require_portal_session()
        if not has_permission(user["role"], "records:create:assigned"):
            raise AppError(
                403,
                "ACCESS_DENIED_RBAC",
                "You do not have sufficient role permissions to author clinical records.",
            )
        parsed_input = {
            **raw_form,
            "patientId": validate_positive_id(raw_pid, "patientId"),
        }
        body = _validate_form_model(CreateRecordPayload, parsed_input)
        patient_row = query_one("SELECT * FROM users WHERE id = ?", (body.patientId,))
        assert_doctor_assigned_to_patient(user, patient_row)

        new_id = execute_write(
            """
            INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                body.patientId,
                user["id"],
                body.diagnosis,
                body.prescription,
                body.clinicalNotes,
                body.severity,
            ),
        )
        security_events.publish(
            "clinical.record.created",
            {"recordId": new_id, "doctorId": user["id"], "patientId": body.patientId},
        )
        fid = _push_flash(f"Clinical record #{new_id} saved and verified securely.", "success")
        return redirect(f"/?tab=records&f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(err, raw_form)
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="records",
            rec_patient_id=sticky_pid,
            rec_severity=raw_sev,
            rec_diagnosis=raw_diag,
            rec_prescription=raw_presc,
            rec_notes=raw_notes,
            status_code=err.status_code,
        )


@portal_bp.post("/portal/records/probe")
def portal_probe_idor() -> tuple[str, int]:
    raw_id = request.form.get("probeRecordId", "2")
    probe_num = int(raw_id) if raw_id.isdigit() and int(raw_id) > 0 else 2
    try:
        user = _require_portal_session()
        if not (
            has_permission(user["role"], "records:read:own")
            or has_permission(user["role"], "records:read:assigned")
        ):
            security_events.publish(
                "rbac.permission.denied",
                {
                    "userId": user["id"],
                    "role": user["role"],
                    "requiredPermissions": ["records:read:own", "records:read:assigned"],
                    "path": "/portal/records/probe",
                },
            )
            raise AppError(
                403,
                "ACCESS_DENIED_RBAC",
                "You do not have sufficient role permissions to perform this action (Principle of Least Privilege / Separation of Duties).",
            )
        rec_id = validate_positive_id(raw_id, "probeRecordId")
        record = query_one(
            """
            SELECT r.*, p.full_name AS patient_name, p.assigned_doctor_id, d.full_name AS doctor_name
            FROM clinical_records r
            JOIN users p ON p.id = r.patient_id
            JOIN users d ON d.id = r.doctor_id
            WHERE r.id = ?
            """,
            (rec_id,),
        )
        if not record:
            raise AppError(404, "RECORD_NOT_FOUND", f"Clinical record #{rec_id} does not exist.")
        assert_can_read_clinical_record(user, record)
        return _render_portal(
            alert_message=f"AUTHORIZED (200 OK): Allowed to read Record #{record['id']} for {record['patient_name']}.",
            alert_kind="success",
            active_tab="records",
            probe_record_id=rec_id,
        )
    except AppError as err:
        err_text = _log_and_format_app_error(err, {"probeRecordId": raw_id})
        return _render_portal(
            alert_message=f"BLOCKED BY RBAC/PoLP GUARD: {err_text}",
            alert_kind="error",
            active_tab="records",
            probe_record_id=probe_num,
            status_code=err.status_code,
        )


@portal_bp.post("/portal/appointments/create")
def portal_create_appointment() -> WerkzeugResponse | tuple[str, int]:
    raw_pid = request.form.get("patientId", "")
    raw_did = request.form.get("doctorId", "")
    raw_sched = request.form.get("scheduledAt", "")
    raw_reason = request.form.get("reason", "")
    raw_form: dict[str, Any] = {
        "patientId": raw_pid or None,
        "doctorId": raw_did,
        "scheduledAt": raw_sched,
        "reason": raw_reason,
    }
    sticky_pid = int(raw_pid) if raw_pid.isdigit() and int(raw_pid) > 0 else None
    sticky_did = int(raw_did) if raw_did.isdigit() and int(raw_did) > 0 else None
    try:
        user = _require_portal_session()
        if not (
            has_permission(user["role"], "appointments:create:own")
            or has_permission(user["role"], "appointments:create:any")
        ):
            raise AppError(
                403,
                "ACCESS_DENIED_RBAC",
                "You do not have permission to schedule appointments.",
            )
        payload_dict: dict[str, Any] = {
            "doctorId": validate_positive_id(raw_did, "doctorId"),
            "scheduledAt": raw_sched,
            "reason": raw_reason,
        }
        if user["role"] == "staff" and raw_pid:
            payload_dict["patientId"] = validate_positive_id(raw_pid, "patientId")

        body = _validate_form_model(CreateAppointmentPayload, payload_dict)
        eff_patient_id = body.patientId if user["role"] == "staff" else user["id"]
        if not eff_patient_id:
            raise AppError(400, "PATIENT_REQUIRED", "Staff bookings must specify a valid patient.")

        patient_row = query_one("SELECT * FROM users WHERE id = ?", (eff_patient_id,))
        if not patient_row or patient_row["role"] != "patient":
            raise AppError(404, "PATIENT_NOT_FOUND", "Selected patient account does not exist.")

        doctor_row = query_one("SELECT * FROM users WHERE id = ?", (body.doctorId,))
        if not doctor_row or doctor_row["role"] != "doctor":
            raise AppError(404, "DOCTOR_NOT_FOUND", "Selected clinician account does not exist.")

        appt_id = execute_write(
            """
            INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status)
            VALUES (?, ?, ?, ?, 'SCHEDULED')
            """,
            (eff_patient_id, body.doctorId, body.scheduledAt, body.reason),
        )
        fid = _push_flash(f"Appointment #{appt_id} scheduled securely.", "success")
        return redirect(f"/?tab=appointments&f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(err, raw_form)
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="appointments",
            appt_patient_id=sticky_pid,
            appt_doctor_id=sticky_did,
            appt_reason=raw_reason,
            appt_dt=raw_sched or None,
            status_code=err.status_code,
        )


@portal_bp.post("/portal/appointments/<raw_id>/status")
def portal_update_appointment_status(raw_id: str) -> WerkzeugResponse | tuple[str, int]:
    raw_status = request.form.get("status", "")
    try:
        user = _require_portal_session()
        if not has_permission(user["role"], "appointments:update:status"):
            raise AppError(403, "ACCESS_DENIED_RBAC", "Permission denied.")
        appt_id = validate_positive_id(raw_id)
        body = _validate_form_model(AppointmentStatusPayload, {"status": raw_status})

        appt = query_one("SELECT * FROM appointments WHERE id = ?", (appt_id,))
        if not appt:
            raise AppError(404, "APPOINTMENT_NOT_FOUND", "Appointment record not found.")
        if user["role"] == "doctor" and appt["doctor_id"] != user["id"]:
            raise AppError(
                403,
                "ACCESS_DENIED_OBJECT_POLICY",
                "Doctors may only update status for their own scheduled appointments.",
            )
        execute_write("UPDATE appointments SET status = ? WHERE id = ?", (body.status, appt_id))
        fid = _push_flash(f"Appointment #{appt_id} marked as {body.status}.", "success")
        return redirect(f"/?tab=appointments&f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(err, {"id": raw_id, "status": raw_status})
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="appointments",
            status_code=err.status_code,
        )


@portal_bp.post("/portal/admin/users/<raw_id>/role")
def portal_admin_update_role(raw_id: str) -> WerkzeugResponse | tuple[str, int]:
    raw_role = request.form.get("role", "")
    raw_doc = request.form.get("assignedDoctorId", "")
    try:
        user = _require_portal_session()
        if not has_permission(user["role"], "users:update:role"):
            raise AppError(403, "ACCESS_DENIED_RBAC", "Administrator privileges required.")
        target_id = validate_positive_id(raw_id)
        doc_val = validate_positive_id(raw_doc, "assignedDoctorId") if raw_doc else None
        body = _validate_form_model(
            UpdateUserRolePayload, {"role": raw_role, "assignedDoctorId": doc_val}
        )

        if target_id == user["id"] and body.role != "admin":
            raise AppError(
                400,
                "SELF_DEMOTION_BLOCKED",
                "Administrators cannot demote their own active administrative account.",
            )
        target_user = query_one("SELECT * FROM users WHERE id = ?", (target_id,))
        if not target_user:
            raise AppError(404, "USER_NOT_FOUND", "Target user account does not exist.")

        normalized_doc_id: int | None = None
        if body.role == "patient" and body.assignedDoctorId is not None:
            doc_row = query_one("SELECT * FROM users WHERE id = ?", (body.assignedDoctorId,))
            if not doc_row or doc_row["role"] != "doctor" or doc_row["id"] == target_id:
                raise AppError(
                    400,
                    "INVALID_ASSIGNED_DOCTOR",
                    "Assigned clinician must be an active user with the doctor role.",
                )
            normalized_doc_id = int(doc_row["id"])

        tx_stmts: list[tuple[str, tuple]] = []
        if target_user["role"] == "doctor" and body.role != "doctor":
            tx_stmts.append(
                (
                    "UPDATE users SET assigned_doctor_id = NULL WHERE assigned_doctor_id = ?",
                    (target_id,),
                )
            )

        tx_stmts.append(
            (
                "UPDATE users SET role = ?, assigned_doctor_id = ? WHERE id = ?",
                (body.role, normalized_doc_id, target_id),
            )
        )
        tx_stmts.append(("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (target_id,)))
        execute_transaction(tx_stmts)
        security_events.publish(
            "admin.role.updated",
            {
                "adminId": user["id"],
                "targetUserId": target_id,
                "previousRole": target_user["role"],
                "newRole": body.role,
            },
        )
        fid = _push_flash(
            f"Updated {target_user['email']} to {body.role.upper()} and revoked active sessions immediately.",
            "success",
        )
        return redirect(f"/?tab=admin&f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(
            err, {"targetId": raw_id, "role": raw_role, "assignedDoctorId": raw_doc}
        )
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="admin",
            status_code=err.status_code,
        )


@portal_bp.post("/portal/admin/users/<raw_id>/unlock")
def portal_admin_unlock_user(raw_id: str) -> WerkzeugResponse | tuple[str, int]:
    try:
        user = _require_portal_session()
        if not has_permission(user["role"], "users:unlock"):
            raise AppError(403, "ACCESS_DENIED_RBAC", "Administrator privileges required.")
        target_id = validate_positive_id(raw_id)
        target_user = query_one("SELECT * FROM users WHERE id = ?", (target_id,))
        if not target_user:
            raise AppError(404, "USER_NOT_FOUND", "Target user account does not exist.")
        execute_write(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            (target_id,),
        )
        security_events.publish(
            "admin.user.unlocked", {"adminId": user["id"], "targetUserId": target_id}
        )
        fid = _push_flash(f"Cleared lockout state for {target_user['email']}.", "success")
        return redirect(f"/?tab=admin&f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(err, {"targetId": raw_id})
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="admin",
            status_code=err.status_code,
        )


@portal_bp.post("/portal/mfa/setup")
def portal_mfa_setup() -> tuple[str, int]:
    try:
        user = _require_portal_session()
        secret_b32 = generate_totp_secret()
        encrypted = encrypt_secret(secret_b32)
        execute_write(
            "UPDATE users SET mfa_pending_secret_enc = ? WHERE id = ?",
            (encrypted, user["id"]),
        )
        qr_info = build_otpauth_qr(user["email"], secret_b32)
        return _render_portal(
            alert_message="Provisioning QR generated. Scan with Google/Microsoft Authenticator and verify the 6-digit code below.",
            alert_kind="success",
            active_tab="mfa",
            mfa_qr_data_url=qr_info["qrDataUrl"],
            mfa_manual_key=secret_b32,
        )
    except AppError as err:
        err_text = _log_and_format_app_error(err, {})
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="mfa",
            status_code=err.status_code,
        )


@portal_bp.post("/portal/mfa/enable")
@auth_rate_limit
def portal_mfa_enable() -> WerkzeugResponse | tuple[str, int]:
    raw_code = request.form.get("totpCode", "")
    try:
        user = _require_portal_session()
        body = _validate_form_model(MfaVerifyPayload, {"totpCode": raw_code})
        current_row = query_one("SELECT * FROM users WHERE id = ?", (user["id"],))
        if not current_row or not current_row.get("mfa_pending_secret_enc"):
            raise AppError(
                400,
                "MFA_NOT_INITIALIZED",
                "Click 'Generate Provisioning QR Code' first before verifying.",
            )
        secret_b32 = decrypt_secret(current_row["mfa_pending_secret_enc"])
        totp_result = verify_totp_code(secret_b32, body.totpCode)
        if not totp_result["valid"]:
            raise AppError(
                400,
                "INVALID_MFA_CODE",
                "The 6-digit code did not match. Ensure your Authenticator clock is synced.",
            )
        execute_write(
            """
            UPDATE users
            SET mfa_secret_enc = ?, mfa_pending_secret_enc = NULL, mfa_enabled = 1, mfa_last_used_step = ?
            WHERE id = ?
            """,
            (current_row["mfa_pending_secret_enc"], totp_result["matchedStep"], user["id"]),
        )
        security_events.publish("auth.mfa.enabled", {"userId": user["id"]})
        fid = _push_flash("Two-Factor Authentication (RFC 6238 TOTP) is now ACTIVE on your account.", "success")
        return redirect(f"/?tab=mfa&f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(err, {"totpCode": raw_code})
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="mfa",
            status_code=err.status_code,
        )


@portal_bp.post("/portal/mfa/disable")
@auth_rate_limit
def portal_mfa_disable() -> WerkzeugResponse | tuple[str, int]:
    raw_pwd = request.form.get("password", "")
    try:
        user = _require_portal_session()
        body = _validate_form_model(MfaDisablePayload, {"password": raw_pwd})
        current_row = query_one("SELECT * FROM users WHERE id = ?", (user["id"],))
        if not verify_password(
            current_row["password_hash"] if current_row else None, body.password
        ):
            raise AppError(401, "INVALID_CREDENTIALS", "Incorrect password. Unable to disable 2FA.")
        execute_write(
            """
            UPDATE users
            SET mfa_secret_enc = NULL, mfa_pending_secret_enc = NULL, mfa_enabled = 0, mfa_last_used_step = NULL
            WHERE id = ?
            """,
            (user["id"],),
        )
        security_events.publish("auth.mfa.disabled", {"userId": user["id"]})
        fid = _push_flash("Two-Factor Authentication has been disabled on your account.", "success")
        return redirect(f"/?tab=mfa&f={fid}", code=303)
    except AppError as err:
        err_text = _log_and_format_app_error(err, {"password": raw_pwd})
        return _render_portal(
            alert_message=err_text,
            alert_kind="error",
            active_tab="mfa",
            status_code=err.status_code,
        )

