"""
Insecure Clinical Record Routes (carevault/routes/record_routes.py)
INTENTIONALLY VULNERABLE BASELINE:
- Insecure Direct Object References (IDOR / BOLA - CWE-639 / OWASP API1:2023)
- Stored Cross-Site Scripting (XSS - CWE-79) via unescaped medical notes
- SQL Injection in search query (CWE-89)
- Missing Cross-Site Request Forgery (CSRF) protections (CWE-352)
"""
from __future__ import annotations

from flask import Blueprint, Response, jsonify, request

from carevault.database import raw_query_all, raw_query_one, raw_execute_write
from carevault.routes.auth_routes import get_current_user

records_bp = Blueprint("records", __name__, url_prefix="/api/records")


@records_bp.get("")
def list_records() -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: Overly permissive - returns all records in system
    records = raw_query_all("SELECT * FROM clinical_records ORDER BY id ASC")
    return jsonify({"status": "ok", "records": records})


@records_bp.get("/<int:record_id>")
def get_record(record_id: int) -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: Horizontal & Vertical IDOR (Broken Object Level Authorization)
    # Does NOT verify if record belongs to current patient or assigned doctor!
    # Patient Nadia (ID 5) can view Patient Daniel's (ID 6) psychiatric record #2!
    sql = f"SELECT * FROM clinical_records WHERE id = {record_id}"
    record = raw_query_one(sql)
    if not record:
        return jsonify({"error": "Record not found"}), 404

    return jsonify({"status": "ok", "record": record})


@records_bp.get("/search")
def search_records() -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    query = request.args.get("q", "")
    # VULNERABILITY: SQL Injection in search parameter
    # Allows UNION SELECT attacks to dump users and password hashes!
    sql = f"SELECT * FROM clinical_records WHERE diagnosis LIKE '%{query}%' OR clinical_notes LIKE '%{query}%'"
    try:
        results = raw_query_all(sql)
        return jsonify({"status": "ok", "query": query, "count": len(results), "records": results})
    except Exception as e:
        # VULNERABILITY: Verbose SQL error message leakage
        return jsonify({"error": f"Database syntax error: {str(e)}"}), 500


@records_bp.post("/create")
def create_record() -> Response:
    user = get_current_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: Broken Access Control - any user can author records, even patients!
    # VULNERABILITY: No CSRF token verification!
    data = request.get_json(silent=True) or request.form.to_dict()

    patient_id = data.get("patientId") or data.get("patient_id")
    diagnosis = data.get("diagnosis", "")
    prescription = data.get("prescription", "")
    clinical_notes = data.get("clinicalNotes") or data.get("clinical_notes", "")
    severity = data.get("severity", "LOW")

    if not patient_id or not diagnosis:
        return jsonify({"error": "Missing patientId or diagnosis"}), 400

    doctor_id = user["id"]

    # VULNERABILITY: Stored XSS - Saves raw HTML/script tags directly into the database!
    sql = (
        f"INSERT INTO clinical_records (patient_id, doctor_id, diagnosis, prescription, clinical_notes, severity) "
        f"VALUES ({patient_id}, {doctor_id}, '{diagnosis}', '{prescription}', '{clinical_notes}', '{severity}')"
    )
    rec_id = raw_execute_write(sql)

    return jsonify({"status": "ok", "message": "Clinical record created successfully", "recordId": rec_id}), 201

