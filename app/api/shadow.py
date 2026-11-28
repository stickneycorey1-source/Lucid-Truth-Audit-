from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Final

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.sanitizer import HomoglyphFinding, InputSanitizer

logger = logging.getLogger("lucid_truth_audit.shadow")

router = APIRouter(prefix="/v1/shadow", tags=["shadow-mode"])

# Singleton sanitizer instance (stateless & thread-safe)
_sanitizer: Final[InputSanitizer] = InputSanitizer(preferred_aliases=["LATIN"])

MAX_METADATA_KEYS: Final[int] = 20
MAX_METADATA_KEY_LEN: Final[int] = 64
MAX_METADATA_VAL_LEN: Final[int] = 256


# ---------------------------------------------------------------------------
# Per-Tenant API Key Authentication (Hashed, Constant-Time Comparison)
# ---------------------------------------------------------------------------
def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _load_tenant_key_map() -> dict[str, str]:
    """
    Maps SHA-256(api_key) -> tenant_id.
    In production, load from KMS / Secrets Manager or an encrypted DB table.
    Env format: LTA_TENANT_KEYS='{"pilot_acme": "raw-or-dev-key"}'
    """
    raw_env = os.getenv("LTA_TENANT_KEYS", "").strip()
    if not raw_env:
        return {}
    try:
        parsed = json.loads(raw_env)
    except json.JSONDecodeError:
        logger.error("shadow.configuration_error invalid_lta_tenant_keys_json")
        return {}

    if not isinstance(parsed, dict):
        logger.error("shadow.configuration_error lta_tenant_keys_not_object")
        return {}

    key_map: dict[str, str] = {}
    for tenant_id, api_key in parsed.items():
        if (
            isinstance(tenant_id, str)
            and isinstance(api_key, str)
            and tenant_id.strip()
            and api_key.strip()
        ):
            key_map[_hash_api_key(api_key.strip())] = tenant_id.strip()
    return key_map


def verify_tenant_api_key(
    authorization: str | None = Header(default=None),
) -> str:
    tenant_map = _load_tenant_key_map()
    if not tenant_map:
        logger.error("shadow.configuration_error missing_tenant_keys")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Shadow authentication is not configured.",
        )

    if not authorization or not authorization[:7].lower() == "bearer ":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer token.",
        )

    raw_token = authorization[7:].strip()
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer token.",
        )

    presented_hash = _hash_api_key(raw_token)
    matched_tenant: str | None = None
    for stored_hash, tenant_id in tenant_map.items():
        if hmac.compare_digest(presented_hash, stored_hash):
            matched_tenant = tenant_id

    if matched_tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid tenant API key.",
        )

    return matched_tenant


# ---------------------------------------------------------------------------
# Pydantic v2 Schemas
# ---------------------------------------------------------------------------
class ShadowIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(..., min_length=1, max_length=100_000)
    request_id: str | None = Field(
        default=None, max_length=128, description="Client-side correlation ID."
    )
    model_target: str | None = Field(
        default=None, max_length=128, description="Downstream LLM name (e.g., gpt-4o)."
    )
    metadata: dict[str, str] = Field(
        default_factory=dict, description="Non-PII operational tags (env, app_id)."
    )

    @field_validator("metadata")
    @classmethod
    def validate_metadata_bounds(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > MAX_METADATA_KEYS:
            raise ValueError(f"metadata cannot exceed {MAX_METADATA_KEYS} entries")
        for key, val in v.items():
            if not key.strip() or len(key) > MAX_METADATA_KEY_LEN:
                raise ValueError(
                    f"metadata keys must be 1..{MAX_METADATA_KEY_LEN} non-blank characters"
                )
            if len(val) > MAX_METADATA_VAL_LEN:
                raise ValueError(
                    f"metadata values cannot exceed {MAX_METADATA_VAL_LEN} characters"
                )
        return v


class ShadowIngestResponse(BaseModel):
    status: str = "accepted"
    audit_id: str
    tenant_id: str
    input_sha256: str
    received_at: datetime


class ZeroRetentionAuditRecord(BaseModel):
    """
    Append-only audit record. Strictly excludes raw prompt text and sanitized text
    to guarantee zero PII retention in logs and compliance ledgers.
    """

    audit_id: str
    tenant_id: str
    request_id: str | None
    model_target: str | None
    timestamp_utc: datetime
    input_sha256: str
    sanitized_sha256: str
    input_length: int
    was_modified: bool
    stripped_cf_count: int
    stripped_cc_count: int
    bidi_override_detected: bool
    nfkc_changed: bool
    homoglyphs_detected: bool
    homoglyph_findings: list[HomoglyphFinding]
    risk_flags: list[str]
    processing_ms: float
    metadata: dict[str, str]


# ---------------------------------------------------------------------------
# Audit Sink & Background Worker
# ---------------------------------------------------------------------------
def write_audit_record(record: ZeroRetentionAuditRecord) -> None:
    """
    Emits structured JSON to the audit logger.
    Swap or extend this sink to write to append-only Postgres / S3 Object Lock.
    """
    logger.info(record.model_dump_json())


def _process_shadow_payload(
    *,
    audit_id: str,
    tenant_id: str,
    input_sha256: str,
    payload: ShadowIngestRequest,
) -> None:
    try:
        started = time.perf_counter()
        result = _sanitizer.sanitize(payload.prompt)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

        sanitized_sha256 = hashlib.sha256(
            result.sanitized_text.encode("utf-8")
        ).hexdigest()

        record = ZeroRetentionAuditRecord(
            audit_id=audit_id,
            tenant_id=tenant_id,
            request_id=payload.request_id,
            model_target=payload.model_target,
            timestamp_utc=datetime.now(timezone.utc),
            input_sha256=input_sha256,
            sanitized_sha256=sanitized_sha256,
            input_length=len(payload.prompt),
            was_modified=result.was_modified,
            stripped_cf_count=result.stripped_cf_count,
            stripped_cc_count=result.stripped_cc_count,
            bidi_override_detected=result.bidi_override_detected,
            nfkc_changed=result.nfkc_changed,
            homoglyphs_detected=result.homoglyphs_detected,
            homoglyph_findings=result.homoglyph_findings,
            risk_flags=result.risk_flags,
            processing_ms=elapsed_ms,
            metadata=payload.metadata,
        )
        write_audit_record(record)
    except Exception as exc:
        logger.error(
            "shadow.worker_failed audit_id=%s tenant=%s error_type=%s",
            audit_id,
            tenant_id,
            type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# Non-Blocking 202 Accepted Endpoint
# ---------------------------------------------------------------------------
@router.post(
    "/ingest",
    response_model=ShadowIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def shadow_ingest(
    payload: ShadowIngestRequest,
    background_tasks: BackgroundTasks,
    tenant_id: str = Depends(verify_tenant_api_key),
) -> ShadowIngestResponse:
    audit_id = f"aud_{uuid.uuid4().hex}"
    input_sha256 = hashlib.sha256(payload.prompt.encode("utf-8")).hexdigest()

    # FastAPI runs sync background functions in a worker threadpool automatically,
    # keeping the main async event loop unblocked.
    background_tasks.add_task(
        _process_shadow_payload,
        audit_id=audit_id,
        tenant_id=tenant_id,
        input_sha256=input_sha256,
        payload=payload,
    )

    return ShadowIngestResponse(
        audit_id=audit_id,
        tenant_id=tenant_id,
        input_sha256=input_sha256,
        received_at=datetime.now(timezone.utc),
    )