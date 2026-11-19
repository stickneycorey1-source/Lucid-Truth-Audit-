import re
from typing import List, Optional, Literal
from fastapi import APIRouter, status
from pydantic import BaseModel, Field, field_validator, model_validator

router = APIRouter(prefix="/api/v1/guard", tags=["Logistics Guard"])

# --- Deterministic Security & PII Patterns ---

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|safety|hos)\s+(instructions|rules|constraints|hos|policies)",
    r"(?i)bypass\s+(weigh\s+station|inspection|geofence|hos|safety)",
    r"(?i)reroute\s+(shipment|cargo|truck)\s+to\s+unverified",
    r"(?i)override\s+(system|dispatch|route)\s+policy",
    r"(?i)system\s+prompt|developer\s+mode|jailbreak",
]

PII_PATTERNS = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CDL": re.compile(r"\b(?:CDL[-\s:]*)?[A-Z]{1,2}\d{6,9}\b", re.IGNORECASE),
    "PHONE": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
}


def redact_pii(text: str) -> tuple[str, List[str]]:
    """Scrubs sensitive driver/manifest PII and returns (cleaned_text, detected_types)."""
    detected = []
    cleaned = text
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(cleaned):
            detected.append(pii_type)
            cleaned = pattern.sub(f"[REDACTED_{pii_type}]", cleaned)
    return cleaned, detected


# --- Pydantic v2 Schemas ---

class Waypoint(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)
    is_authorized_facility: bool = Field(default=True)

    @field_validator("is_authorized_facility")
    @classmethod
    def verify_facility_authorization(cls, v: bool) -> bool:
        if not v:
            raise ValueError("SECURITY_VIOLATION: Unverified or unauthorized waypoint blocked.")
        return v


class DispatchRoutePayload(BaseModel):
    dispatch_id: str = Field(..., min_length=4, max_length=64)
    driver_alias: str = Field(..., min_length=2, max_length=50, description="Anonymized driver callsign")
    vehicle_vin_hash: str = Field(..., min_length=8, max_length=64)

    # FMCSA Property-Carrying HOS Safety Constraints
    planned_drive_hours: float = Field(..., gt=0.0, le=11.0, description="Max 11.0 hrs per FMCSA 49 CFR § 395.3")
    on_duty_window_hours: float = Field(..., gt=0.0, le=14.0, description="Max 14.0 hr consecutive duty window")
    continuous_drive_before_break_hours: float = Field(
        ..., gt=0.0, le=8.0, description="Mandatory 30-min break required at or before 8.0 hrs"
    )
    rest_break_minutes: int = Field(..., ge=30, description="Minimum 30-minute off-duty rest break")

    # Cargo & Weight Integrity
    gross_vehicle_weight_lbs: int = Field(..., gt=0, le=80000, description="Federal interstate weight cap")
    hazmat_class: Optional[Literal["NONE", "1", "2", "3", "4", "5", "6", "7", "8", "9"]] = "NONE"

    # Unstructured Text Fields (High Injection & PII Risk)
    bill_of_lading_notes: str = Field(default="", max_length=2000)
    dispatcher_summary: str = Field(default="", max_length=2000)

    # Route Geometry
    waypoints: List[Waypoint] = Field(..., min_length=2, max_length=25)

    @field_validator("bill_of_lading_notes", "dispatcher_summary")
    @classmethod
    def scan_indirect_prompt_injection(cls, value: str) -> str:
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, value):
                raise ValueError(
                    "SECURITY_VIOLATION: Indirect prompt injection or safety override detected in unstructured text."
                )
        return value

    @model_validator(mode="after")
    def validate_hos_consistency(self) -> "DispatchRoutePayload":
        if self.planned_drive_hours > self.on_duty_window_hours:
            raise ValueError("HOS_VIOLATION: Planned drive hours cannot exceed total on-duty window.")
        return self


class DispatchGuardResponse(BaseModel):
    status: Literal["APPROVED", "APPROVED_WITH_REDACTIONS"]
    dispatch_id: str
    audit_passed: bool
    pii_redacted_types: List[str]
    sanitized_bol_notes: str
    sanitized_dispatcher_summary: str
    compliance_checks: dict


# --- FastAPI Guard Endpoint ---

@router.post("/logistics", response_model=DispatchGuardResponse, status_code=status.HTTP_200_OK)
async def evaluate_dispatch_route(payload: DispatchRoutePayload) -> DispatchGuardResponse:
    """
    Deterministic guardrail endpoint for AI-generated fleet dispatch and routing payloads.
    Blocks HOS violations, unauthorized waypoints, and BOL prompt injections; redacts driver PII.
    """
    clean_bol, bol_pii = redact_pii(payload.bill_of_lading_notes)
    clean_summary, summary_pii = redact_pii(payload.dispatcher_summary)

    all_redacted = sorted(list(set(bol_pii + summary_pii)))
    guard_status = "APPROVED_WITH_REDACTIONS" if all_redacted else "APPROVED"

    return DispatchGuardResponse(
        status=guard_status,
        dispatch_id=payload.dispatch_id,
        audit_passed=True,
        pii_redacted_types=all_redacted,
        sanitized_bol_notes=clean_bol,
        sanitized_dispatcher_summary=clean_summary,
        compliance_checks={
            "fmcsa_hos_compliant": True,
            "geofence_waypoints_verified": True,
            "prompt_injection_clean": True,
            "weight_limit_compliant": True,
        },
    )
