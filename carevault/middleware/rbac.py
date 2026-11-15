"""
Requirement 1: Role-Based Access Control (RBAC), Principle of Least Privilege (PoLP),
Separation of Duties (SoD), and Object-Level Authorization (BOLA / IDOR Prevention).
"""
from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import g, request

from carevault.middleware.error_handler import AppError
from carevault.security.extension_hooks import security_events

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "patient": frozenset(
        {
            "records:read:own",
            "appointments:read:own",
            "appointments:create:own",
            "directory:doctors:read",
            "profile:mfa:manage",
        }
    ),
    "staff": frozenset(
        {
            # PoLP: Receptionist staff coordinate scheduling ONLY — strictly denied clinical records!
            "appointments:read:all",
            "appointments:create:any",
            "appointments:update:status",
            "directory:doctors:read",
            "directory:patients:read",
            "profile:mfa:manage",
        }
    ),
    "doctor": frozenset(
        {
            # PoLP: Clinicians access clinical records ONLY for patients assigned to their care!
            "records:read:assigned",
            "records:create:assigned",
            "appointments:read:assigned",
            "appointments:update:status",
            "directory:doctors:read",
            "directory:patients:assigned",
            "profile:mfa:manage",
        }
    ),
    "admin": frozenset(
        {
            # Separation of Duties: Admins govern accounts, roles & PKI — NOT clinical diagnoses!
            "users:read:all",
            "users:update:role",
            "users:unlock",
            "directory:doctors:read",
            "security:pki:inspect",
            "profile:mfa:manage",
        }
    ),
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def require_any_permission(*required_permissions: str) -> Callable[..., Any]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            user = getattr(g, "user", None)
            if not user:
                raise AppError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")

            allowed = any(has_permission(user["role"], perm) for perm in required_permissions)
            if not allowed:
                security_events.publish(
                    "rbac.permission.denied",
                    {
                        "userId": user["id"],
                        "role": user["role"],
                        "requiredPermissions": list(required_permissions),
                        "path": request.path,
                    },
                )
                raise AppError(
                    403,
                    "ACCESS_DENIED_RBAC",
                    "You do not have sufficient role permissions to perform this action (Principle of Least Privilege).",
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def assert_can_read_clinical_record(user: dict[str, Any], record: dict[str, Any]) -> None:
    if user["role"] == "patient" and record["patient_id"] == user["id"]:
        return
    if user["role"] == "doctor" and (
        record["doctor_id"] == user["id"] or record.get("assigned_doctor_id") == user["id"]
    ):
        return

    security_events.publish(
        "rbac.idor.blocked",
        {
            "userId": user["id"],
            "role": user["role"],
            "targetRecordId": record["id"],
            "recordOwnerId": record["patient_id"],
        },
    )
    raise AppError(
        403,
        "ACCESS_DENIED_OBJECT_POLICY",
        "Access denied: You are not authorized to view this specific clinical record.",
    )


def assert_doctor_assigned_to_patient(
    doctor_user: dict[str, Any], patient_row: dict[str, Any] | None
) -> None:
    if not patient_row or patient_row["role"] != "patient":
        raise AppError(404, "PATIENT_NOT_FOUND", "Target patient account does not exist.")
    if patient_row["assigned_doctor_id"] != doctor_user["id"]:
        security_events.publish(
            "rbac.unassigned_patient.blocked",
            {
                "doctorId": doctor_user["id"],
                "targetPatientId": patient_row["id"],
            },
        )
        raise AppError(
            403,
            "ACCESS_DENIED_UNASSIGNED_PATIENT",
            "Principle of Least Privilege: Doctors may only author clinical records for patients assigned to their care.",
        )

