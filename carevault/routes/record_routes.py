"""
Requirement 1 & 2: RBAC, PoLP & IDOR-Protected Clinical Records Routes
"""
from __future__ import annotations

from flask import Blueprint, Response, g, jsonify

from carevault.database import execute_write, query_all, query_one
from carevault.middleware.auth import require_auth
from carevault.middleware.error_handler import AppError
from carevault.middleware.rbac import (
    assert_can_read_clinical_record,
    assert_doctor_assigned_to_patient,
    require_any_permission,
)
from carevault.security.encoding import encode_record_for_safe_display
from carevault.security.extension_hooks import security_events
from carevault.security.validation import (
    CreateRecordPayload,
    parse_json_body,
    validate_positive_id,
)

records_bp = Blueprint("records", __name__, url_prefix="/api/records")


@records_bp.get("")
@records_bp.get("/")
@require_auth
@require_any_permission("records:read:own", "records:read:assigned")
def list_records() -> Response:
    user = g.user
    rows: list[dict] = []
    if user["role"] == "patient":
        rows = query_all(
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
    elif user["role"] == "doctor":
        rows = query_all(
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

    return jsonify(
        {
            "status": "success",
            "records": [encode_record_for_safe_display(r) for r in rows],
        }
    )


@records_bp.get("/<raw_id>")
@require_auth
@require_any_permission("records:read:own", "records:read:assigned")
def get_record_by_id(raw_id: str) -> Response:
    record_id = validate_positive_id(raw_id)
    record = query_one(
        """
        SELECT r.*, p.full_name AS patient_name, p.assigned_doctor_id, d.full_name AS doctor_name
        FROM clinical_records r
        JOIN users p ON p.id = r.patient_id
        JOIN users d ON d.id = r.doctor_id
        WHERE r.id = ?
        """,
        (record_id,),
    )
    if not record:
        raise AppError(404, "RECORD_NOT_FOUND", "Clinical record not found.")

    assert_can_read_clinical_record(g.user, record)
    return jsonify(
        {
            "status": "success",
            "record": encode_record_for_safe_display(record),
        }
    )


@records_bp.post("")
@records_bp.post("/")
@require_auth
@require_any_permission("records:create:assigned")
def create_record() -> tuple[Response, int]:
    body = parse_json_body(CreateRecordPayload)
    patient_row = query_one("SELECT * FROM users WHERE id = ?", (body.patientId,))
    assert_doctor_assigned_to_patient(g.user, patient_row)

    new_id = execute_write(
        """
        INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            body.patientId,
            g.user["id"],
            body.diagnosis,
            body.prescription,
            body.clinicalNotes,
            body.severity,
        ),
    )

    created = query_one(
        """
        SELECT r.*, p.full_name AS patient_name, p.assigned_doctor_id, d.full_name AS doctor_name
        FROM clinical_records r
        JOIN users p ON p.id = r.patient_id
        JOIN users d ON d.id = r.doctor_id
        WHERE r.id = ?
        """,
        (new_id,),
    )
    security_events.publish(
        "clinical.record.created",
        {"recordId": new_id, "doctorId": g.user["id"], "patientId": body.patientId},
    )

    return (
        jsonify(
            {
                "status": "success",
                "message": "Clinical record saved securely.",
                "record": encode_record_for_safe_display(created or {}),
            }
        ),
        201,
    )

