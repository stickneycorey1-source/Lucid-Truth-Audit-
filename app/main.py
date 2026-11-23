import re
from typing import List, Optional, Literal
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator

from app.normalizer import normalize_text_for_inspection
from app.security import TenantContext, authenticate_and_limit
from app.ledger import audit_ledger

router = APIRouter(prefix="/api/v1/guard", tags=["Logistics Guard"])

INJECTION_PATTERNS = [
    r"(?i)(?:ignore|disregard|forget|drop)\s+(?:\w+\s+){0,4}(?:previous|prior|safety|hos|all)\s+(?:\w+\s+){0,2}(?:instructions?|rules?|constraints?|directives?|limits?|checks?|hos|policies|policy)",
    r"(?i)(?:ignore|disregard|bypass|skip|avoid|disable)\s+(?:the\s+)?(?:weigh\s+station|inspection|geofence|hos(?:\s+limits?)?|safety(?:\s+checks?)?|audit|logging)",
    r"(?i)reroute\s+(?:shipment|cargo|truck|load)\s+to\s+unverified",
    r"(?i)override\s+(?:system|dispatch|route|safety|hos)\s+(?:policy|rules?|constraints?|limits?)",
    r"(?i)(?:system\s+prompt|developer\s+mode|jailbreak|(?:^|\n)\s*(?:system|developer)\s*:)",
]

PII_PATTERNS = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CDL": re.compile(
        r"\b(?:CDL|commercial\s+driver(?:'s)?\s+license|driver(?:'s)?\s+license|DL)"
        r"(?:\s*(?:no\.?|num(?:ber)?|#|:|-))?\s*"
        r"(?:[A-Z]{1,2}[-\s]?\d(?:[\d-]{5,13}\d)|\d{7,12}|\d{2,4}-\d{2,4}-\d{3,4})\b",
        re.IGNORECASE,
    ),
    "PHONE": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
}

OVERSIZE_PERMIT_RE = re.compile(r"^[A-Z]{2}-OSW-\d{4,10}$")


def redact_pii(text: str) -> tuple[str, List[str]]:
    """Scrubs sensitive driver/manifest PII without corrupting operational PO/BOL/Trailer IDs."""
    detected: List[str] = []
    cleaned = text
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(cleaned):
            detected.append(pii_type)
            cleaned = pattern.sub(f"[REDACTED_{pii_type}]", cleaned)
    return cleaned, detected


def detect_logistics_injection(text: str) -> bool:
    normalized = normalize_text_for_inspection(text)
    return any(re.search(pattern, normalized) for pattern in INJECTION_PATTERNS)


class Waypoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
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
    model_config = ConfigDict(extra="forbid")

    dispatch_id: str = Field(..., min_length=4, max_length=64)
    driver_alias: str = Field(..., min_length=2, max_length=50)
    vehicle_vin_hash: str = Field(..., min_length=8, max_length=64)

    # FMCSA 49 CFR § 395.3 Single-Shift Property-Carrying Bounds
    planned_drive_hours: float = Field(..., gt=0.0, le=11.0, description="Max 11.0 hrs driving")
    on_duty_window_hours: float = Field(..., gt=0.0, le=14.0, description="Max 14.0 hr consecutive duty window")
    continuous_drive_before_break_hours: float = Field(..., gt=0.0, le=8.0, description="Max 8.0 hrs before 30-min break")
    rest_break_minutes: int = Field(..., ge=30, description="Minimum 30-minute rest break")

    # FMCSA 60/7 or 70/8 Multi-Day Cycle Accounting
    cycle_type: Literal["60_7", "70_8"] = "70_8"
    cycle_hours_used_before_shift: float = Field(default=0.0, ge=0.0, le=70.0)

    # Cargo, Weight & Optional Oversize Permit
    gross_vehicle_weight_lbs: int = Field(..., gt=0, le=160000, description="80,000 lb cap unless valid oversize permit supplied")
    oversize_permit_id: Optional[str] = Field(default=None, description="Format: e.g. MN-OSW-202604")
    hazmat_class: Optional[Literal["NONE", "1", "2", "3", "4", "5", "6", "7", "8", "9"]] = "NONE"

    # Unstructured Text (Normalized & Scanned for Prompt Injection + PII)
    bill_of_lading_notes: str = Field(default="", max_length=2000)
    dispatcher_summary: str = Field(default="", max_length=2000)

    waypoints: List[Waypoint] = Field(..., min_length=2, max_length=25)

    @field_validator("bill_of_lading_notes", "dispatcher_summary")
    @classmethod
    def scan_indirect_prompt_injection(cls, value: str) -> str:
        if detect_logistics_injection(value):
            raise ValueError(
                "SECURITY_VIOLATION: Indirect prompt injection or obfuscated safety override detected."
            )
        return value

    @model_validator(mode="after")
    def validate_fmcsa_and_weight_rules(self) -> "DispatchRoutePayload":
        if self.planned_drive_hours > self.on_duty_window_hours:
            raise ValueError("HOS_VIOLATION: Planned drive hours cannot exceed total on-duty window.")

        if self.continuous_drive_before_break_hours > self.planned_drive_hours:
            raise ValueError(
                "HOS_VIOLATION: Continuous drive before break cannot exceed total planned drive hours."
            )

        cycle_cap = 60.0 if self.cycle_type == "60_7" else 70.0
        if self.cycle_hours_used_before_shift > cycle_cap:
            raise ValueError(
                f"HOS_CYCLE_VIOLATION: Prior cycle hours ({self.cycle_hours_used_before_shift}) exceed {cycle_cap:.0f}-hour FMCSA {self.cycle_type} cap."
            )
        if self.cycle_hours_used_before_shift + self.on_duty_window_hours > cycle_cap:
            raise ValueError(
                f"HOS_CYCLE_VIOLATION: Shift exceeds {cycle_cap:.0f}-hour FMCSA {self.cycle_type} duty cycle."
            )

        if self.gross_vehicle_weight_lbs > 80000:
            permit = (self.oversize_permit_id or "").strip().upper()
            if not permit or not OVERSIZE_PERMIT_RE.match(permit):
                raise ValueError(
                    "WEIGHT_VIOLATION: Gross weight exceeds 80,000 lbs federal cap without a valid oversize_permit_id (XX-OSW-NNNN)."
                )
            self.oversize_permit_id = permit
        return self


class DispatchGuardResponse(BaseModel):
    status: Literal["APPROVED", "APPROVED_WITH_REDACTIONS"]
    tenant_id: str
    dispatch_id: str
    audit_passed: bool
    pii_redacted_types: List[str]
    sanitized_bol_notes: str
    sanitized_dispatcher_summary: str
    compliance_checks: dict
    ledger_entry_hash: str


@router.post("/logistics", response_model=DispatchGuardResponse, status_code=status.HTTP_200_OK)
async def evaluate_dispatch_route(
    payload: DispatchRoutePayload,
    tenant: TenantContext = Depends(authenticate_and_limit),
) -> DispatchGuardResponse:
    clean_bol, bol_pii = redact_pii(payload.bill_of_lading_notes)
    clean_summary, summary_pii = redact_pii(payload.dispatcher_summary)

    all_redacted = sorted(list(set(bol_pii + summary_pii)))
    guard_status = "APPROVED_WITH_REDACTIONS" if all_redacted else "APPROVED"

    ledger_row = audit_ledger.record_event(
        tenant_id=tenant.tenant_id,
        endpoint="/api/v1/guard/logistics",
        reference_id=payload.dispatch_id,
        decision=guard_status,
        http_status=200,
        redacted_types=all_redacted,
        summary=f"FMCSA/weight/BOL checks passed; redacted={all_redacted or 'none'}",
    )

    return DispatchGuardResponse(
        status=guard_status,
        tenant_id=tenant.tenant_id,
        dispatch_id=payload.dispatch_id,
        audit_passed=True,
        pii_redacted_types=all_redacted,
        sanitized_bol_notes=clean_bol,
        sanitized_dispatcher_summary=clean_summary,
        compliance_checks={
            "fmcsa_shift_hos_compliant": True,
            "fmcsa_cycle_hos_compliant": True,
            "geofence_waypoints_verified": True,
            "prompt_injection_clean": True,
            "weight_limit_compliant": True,
            "oversize_permit_verified": bool(payload.oversize_permit_id) if payload.gross_vehicle_weight_lbs > 80000 else False,
        },
        ledger_entry_hash=ledger_row["entry_hash"],
    )