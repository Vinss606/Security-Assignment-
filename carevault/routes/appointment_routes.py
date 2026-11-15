"""
Requirement 1 & 2: Clinical Appointments & PoLP Directory Routes
"""
from __future__ import annotations

from flask import Blueprint, Response, g, jsonify

from carevault.database import execute_write, query_all, query_one
from carevault.middleware.auth import require_auth
from carevault.middleware.error_handler import AppError
from carevault.middleware.rbac import require_any_permission
from carevault.security.encoding import encode_html
from carevault.security.validation import (
    AppointmentStatusPayload,
    CreateAppointmentPayload,
    parse_json_body,
    validate_positive_id,
)

appointments_bp = Blueprint("appointments", __name__, url_prefix="/api/appointments")


@appointments_bp.get("/directory")
@require_auth
@require_any_permission(
    "directory:doctors:read", "directory:patients:read", "directory:patients:assigned"
)
def directory() -> Response:
    doctors = query_all(
        "SELECT id, full_name, email FROM users WHERE role = 'doctor' ORDER BY full_name ASC"
    )
    patients: list[dict] = []
    if g.user["role"] == "staff":
        patients = query_all(
            "SELECT id, full_name, email, phone, assigned_doctor_id FROM users WHERE role = 'patient' ORDER BY full_name ASC"
        )
    elif g.user["role"] == "doctor":
        patients = query_all(
            """
            SELECT id, full_name, email, phone, assigned_doctor_id FROM users
            WHERE role = 'patient' AND assigned_doctor_id = ?
            ORDER BY full_name ASC
            """,
            (g.user["id"],),
        )
    return jsonify({"status": "success", "doctors": doctors, "patients": patients})


@appointments_bp.get("")
@appointments_bp.get("/")
@require_auth
@require_any_permission(
    "appointments:read:own", "appointments:read:assigned", "appointments:read:all"
)
def list_appointments() -> Response:
    rows: list[dict] = []
    role = g.user["role"]
    if role == "patient":
        rows = query_all(
            """
            SELECT a.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM appointments a
            JOIN users p ON p.id = a.patient_id
            JOIN users d ON d.id = a.doctor_id
            WHERE a.patient_id = ?
            ORDER BY a.scheduled_at ASC
            """,
            (g.user["id"],),
        )
    elif role == "doctor":
        rows = query_all(
            """
            SELECT a.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM appointments a
            JOIN users p ON p.id = a.patient_id
            JOIN users d ON d.id = a.doctor_id
            WHERE a.doctor_id = ?
            ORDER BY a.scheduled_at ASC
            """,
            (g.user["id"],),
        )
    elif role == "staff":
        rows = query_all(
            """
            SELECT a.*, p.full_name AS patient_name, d.full_name AS doctor_name
            FROM appointments a
            JOIN users p ON p.id = a.patient_id
            JOIN users d ON d.id = a.doctor_id
            ORDER BY a.scheduled_at ASC
            """
        )

    return jsonify(
        {
            "status": "success",
            "appointments": [{**r, "reasonSafeHtml": encode_html(r["reason"])} for r in rows],
        }
    )


@appointments_bp.post("")
@appointments_bp.post("/")
@require_auth
@require_any_permission("appointments:create:own", "appointments:create:any")
def create_appointment() -> tuple[Response, int]:
    body = parse_json_body(CreateAppointmentPayload)
    effective_patient_id = body.patientId if g.user["role"] == "staff" else g.user["id"]

    if not effective_patient_id:
        raise AppError(400, "PATIENT_REQUIRED", "Staff bookings must specify a valid patient ID.")

    patient_row = query_one("SELECT * FROM users WHERE id = ?", (effective_patient_id,))
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
        (effective_patient_id, body.doctorId, body.scheduledAt, body.reason),
    )
    return (
        jsonify(
            {
                "status": "success",
                "message": "Appointment scheduled.",
                "appointmentId": appt_id,
            }
        ),
        201,
    )


@appointments_bp.patch("/<raw_id>/status")
@require_auth
@require_any_permission("appointments:update:status")
def update_status(raw_id: str) -> Response:
    appt_id = validate_positive_id(raw_id)
    body = parse_json_body(AppointmentStatusPayload)

    appt = query_one("SELECT * FROM appointments WHERE id = ?", (appt_id,))
    if not appt:
        raise AppError(404, "APPOINTMENT_NOT_FOUND", "Appointment record not found.")

    if g.user["role"] == "doctor" and appt["doctor_id"] != g.user["id"]:
        raise AppError(
            403,
            "ACCESS_DENIED_OBJECT_POLICY",
            "Doctors may only update status for their own scheduled appointments.",
        )

    execute_write("UPDATE appointments SET status = ? WHERE id = ?", (body.status, appt_id))
    return jsonify({"status": "success", "message": "Appointment status updated."})

