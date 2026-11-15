"""
Requirement 2: Strict Input Validation & Sanitization Layer (`pydantic` v2)
- Enforces `ConfigDict(extra='forbid')` allowlists to block JSON Mass Assignment (OWASP A01/A04)
- Normalizes Unicode strings (`NFC`) and strips null bytes + non-printable ASCII control chars
- Validates real calendar dates, domain enumerations, regex bounds, and positive integer IDs
"""
from __future__ import annotations

import datetime as dt
import re
import unicodedata
from typing import Any, Literal, TypeVar

from flask import request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from werkzeug.exceptions import BadRequest

from carevault.middleware.error_handler import AppError

T = TypeVar("T", bound=BaseModel)

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
_NAME_RE = re.compile(r"^[a-zA-Z\s.'()/,-]+$")
_PHONE_RE = re.compile(r"^[0-9+\s()-]{8,20}$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")


def sanitize_text_string(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    normalized = unicodedata.normalize("NFC", raw)
    return _CTRL_CHARS_RE.sub("", normalized).strip()


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterPayload(StrictSchema):
    fullName: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=12, max_length=128)
    phone: str = Field(min_length=8, max_length=20)

    @field_validator("fullName", mode="before")
    @classmethod
    def clean_name(cls, v: Any) -> Any:
        s = sanitize_text_string(v)
        if isinstance(s, str) and not _NAME_RE.fullmatch(s):
            raise ValueError(
                "Full name may only contain letters, spaces, dots, hyphens, and apostrophes."
            )
        return s

    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, v: Any) -> Any:
        s = sanitize_text_string(v)
        if isinstance(s, str):
            s = s.lower()
            if not _EMAIL_RE.fullmatch(s):
                raise ValueError("Please provide a valid email address.")
        return s

    @field_validator("phone", mode="before")
    @classmethod
    def clean_phone(cls, v: Any) -> Any:
        s = sanitize_text_string(v)
        if isinstance(s, str) and (
            not _PHONE_RE.fullmatch(s) or len(re.findall(r"\d", s)) < 7
        ):
            raise ValueError("Phone number must be 8-20 characters containing at least 7 digits.")
        return s


class LoginPayload(StrictSchema):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=1, max_length=128)
    totpCode: str | None = None

    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, v: Any) -> Any:
        s = sanitize_text_string(v)
        if isinstance(s, str):
            s = s.lower()
            if not _EMAIL_RE.fullmatch(s):
                raise ValueError("Please provide a valid email address.")
        return s

    @field_validator("totpCode", mode="before")
    @classmethod
    def check_totp(cls, v: Any) -> Any:
        if v is None or v == "":
            return None
        s = sanitize_text_string(v)
        if isinstance(s, str):
            s = re.sub(r"[\s-]+", "", s)
        if not isinstance(s, str) or not re.fullmatch(r"\d{6}", s):
            raise ValueError("MFA code must be a 6-digit number.")
        return s


class MfaVerifyPayload(StrictSchema):
    totpCode: str

    @field_validator("totpCode", mode="before")
    @classmethod
    def check_code(cls, v: Any) -> Any:
        s = sanitize_text_string(v)
        if isinstance(s, str):
            s = re.sub(r"[\s-]+", "", s)
        if not isinstance(s, str) or not re.fullmatch(r"\d{6}", s):
            raise ValueError("Authenticator code must be exactly 6 digits.")
        return s


class MfaDisablePayload(StrictSchema):
    password: str = Field(min_length=1, max_length=128)


class CreateRecordPayload(StrictSchema):
    patientId: int = Field(gt=0)
    diagnosis: str = Field(min_length=3, max_length=200)
    prescription: str = Field(min_length=2, max_length=300)
    clinicalNotes: str = Field(min_length=5, max_length=2000)
    severity: Literal["LOW", "MODERATE", "HIGH", "CRITICAL"]

    @field_validator("diagnosis", "prescription", "clinicalNotes", mode="before")
    @classmethod
    def strip_text(cls, v: Any) -> Any:
        return sanitize_text_string(v)


class CreateAppointmentPayload(StrictSchema):
    patientId: int | None = Field(default=None, gt=0)
    doctorId: int = Field(gt=0)
    scheduledAt: str
    reason: str = Field(min_length=4, max_length=250)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_reason(cls, v: Any) -> Any:
        return sanitize_text_string(v)

    @field_validator("scheduledAt", mode="before")
    @classmethod
    def validate_datetime_str(cls, v: Any) -> Any:
        raw_str = sanitize_text_string(v) if isinstance(v, str) else ""
        cleaned = re.sub(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}):\d{2}$", r"\1", raw_str)
        if not _DATETIME_RE.fullmatch(cleaned):
            raise ValueError("Appointment date must match YYYY-MM-DDTHH:mm format.")
        try:
            dt.datetime.strptime(cleaned, "%Y-%m-%dT%H:%M").replace(tzinfo=dt.UTC)
        except ValueError as exc:
            raise ValueError("Appointment date must be a valid calendar date and time.") from exc
        return cleaned


class AppointmentStatusPayload(StrictSchema):
    status: Literal["SCHEDULED", "COMPLETED", "CANCELLED"]


class UpdateUserRolePayload(StrictSchema):
    role: Literal["patient", "staff", "doctor", "admin"]
    assignedDoctorId: int | None = Field(default=None, gt=0)


def parse_json_body(model_cls: type[T]) -> T:
    if not request.is_json:
        raise BadRequest("Expected application/json payload.")
    raw_data = request.get_json(silent=False)
    if not isinstance(raw_data, dict):
        raise BadRequest("JSON payload must be an object.")
    try:
        return model_cls.model_validate(raw_data)
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


def validate_positive_id(raw_id: Any, label: str = "id") -> int:
    try:
        val = int(raw_id)
        if val <= 0:
            raise ValueError
        return val
    except (TypeError, ValueError) as exc:
        raise AppError(
            400,
            "VALIDATION_ERROR",
            "Invalid URL parameters supplied.",
            [{"field": label, "message": "Resource ID must be a valid positive integer."}],
        ) from exc

