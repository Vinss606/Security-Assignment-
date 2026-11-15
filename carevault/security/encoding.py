"""
Requirement 2: Context-Aware Output Encoding Utilities (OWASP XSS Prevention Cheat Sheet)
Prevents Stored and Reflected Cross-Site Scripting (XSS) across HTML Body and HTML Attribute
contexts alongside strict Pure Python `Content-Security-Policy: script-src 'none'`.
"""
from __future__ import annotations

from typing import Any

_HTML_MAP = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "/": "&#x2F;",
    "`": "&#x60;",
}


def encode_html(value: Any) -> str:
    if value is None:
        return ""
    return "".join(_HTML_MAP.get(ch, ch) for ch in str(value))


def encode_html_attribute(value: Any) -> str:
    if value is None:
        return ""
    out: list[str] = []
    for ch in str(value):
        if ch.isalnum() and ch.isascii():
            out.append(ch)
        elif ord(ch) < 256:
            out.append(f"&#x{ord(ch):02x};")
        else:
            out.append(_HTML_MAP.get(ch, ch))
    return "".join(out)


def encode_record_for_safe_display(record: dict[str, Any]) -> dict[str, Any]:
    return {
        **record,
        "encoded": {
            "diagnosisHtml": encode_html(record.get("diagnosis")),
            "clinicalNotesHtml": encode_html(record.get("clinical_notes")),
            "prescriptionHtml": encode_html(record.get("prescription")),
            "patientNameAttr": encode_html_attribute(record.get("patient_name", "")),
        },
    }

