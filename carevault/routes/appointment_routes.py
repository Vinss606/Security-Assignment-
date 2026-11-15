"""
Insecure Appointment Routes (carevault/routes/appointment_routes.py)
INTENTIONALLY VULNERABLE BASELINE:
- Missing CSRF validation on appointment creation and status change
- IDOR: Any patient can cancel or reschedule any other patient's appointment
"""
from __future__ import annotations

from flask import Blueprint, Response, jsonify, request

from carevault.database import raw_query_all, raw_query_one, raw_execute_write
from carevault.routes.auth_routes import get_current_user

appointments_bp = Blueprint("appointments", __name__, url_prefix="/api/appointments")


@appointments_bp.get("")
def list_appointments() -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: Overly permissive - returns all appointments
    appts = raw_query_all("SELECT * FROM appointments ORDER BY scheduled_at ASC")
    return jsonify({"status": "ok", "appointments": appts})


@appointments_bp.post("/create")
def create_appointment() -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: No CSRF verification!
    data = request.get_json(silent=True) or request.form.to_dict()
    patient_id = data.get("patientId") or data.get("patient_id") or user["id"]
    doctor_id = data.get("doctorId") or data.get("doctor_id") or 2
    scheduled_at = data.get("scheduledAt") or data.get("scheduled_at", "")
    reason = data.get("reason", "")

    # VULNERABILITY: Stored XSS in reason
    sql = (
        f"INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status) "
        f"VALUES ({patient_id}, {doctor_id}, '{scheduled_at}', '{reason}', 'SCHEDULED')"
    )
    appt_id = raw_execute_write(sql)
    return jsonify({"status": "ok", "message": "Appointment booked", "appointmentId": appt_id}), 201


@appointments_bp.post("/<int:appt_id>/status")
def update_status(appt_id: int) -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: IDOR - No check whether user is authorized to change this appointment
    data = request.get_json(silent=True) or request.form.to_dict()
    status = data.get("status", "COMPLETED")
    raw_execute_write(f"UPDATE appointments SET status = '{status}' WHERE id = {appt_id}")
    return jsonify({"status": "ok", "message": "Status updated"})

