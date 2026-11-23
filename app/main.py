import os
import csv
import io
import math
import re
import logging
from pathlib import Path
from typing import Any, List, Optional, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ConfigDict

from app.normalizer import normalize_text_for_inspection
from app.security import TenantContext, authenticate_and_limit
try:
    from app.security import verify_key_and_limit_raw
except ImportError:
    from app.security import resolve_valid_tenant

    def verify_key_and_limit_raw(x_api_key: Optional[str]):
        tenant = resolve_valid_tenant(x_api_key)
        if tenant is None:
            return None, status.HTTP_401_UNAUTHORIZED, "Invalid, expired, or missing API key."
        return tenant, status.HTTP_200_OK, ""

from app.ledger import audit_ledger
from app.evidence_chain import EvidenceChainStore, DuplicateEvidenceError
from app.schemas.logistics_guard import router as logistics_router

logger = logging.getLogger("lucid_truth_audit")

FRAMEWORK_VERSION = "2.0.3"

app = FastAPI(
    title="Lucid-Truth-Audit",
    version=FRAMEWORK_VERSION,
    description="Production Deterministic AI Security, PII Redaction, Evidence Chain, and FMCSA Fleet Compliance Engine",
)

# Configurable CORS allowlist for external portals (e.g., Vercel React frontend)
_cors_raw = os.getenv("LUCID_CORS_ORIGINS", "").strip()
_cors_origins = [o.strip() for o in _cors_raw.split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

app.include_router(logistics_router)


# --- Security Headers Middleware ---

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Allow Swagger UI / ReDoc CDN assets only on documentation endpoints; keep strict CSP everywhere else
    if request.url.path in ("/docs", "/redoc", "/docs/oauth2-redirect"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; frame-ancestors 'none';"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
        )
    return response


# --- Global Validation Error Handler (Auth + Rate-Limit Gated, Pydantic v2 JSON-Safe) ---

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/api/v1/guard"):
        tenant, auth_code, auth_detail = verify_key_and_limit_raw(request.headers.get("X-API-Key"))
        if tenant is None:
            return JSONResponse(status_code=auth_code, content={"detail": auth_detail})

        reasons = "; ".join(err.get("msg", "validation_error") for err in exc.errors())
        ref_id = "BLOCKED_SCHEMA"
        if isinstance(exc.body, dict) and isinstance(exc.body.get("dispatch_id"), str):
            ref_id = exc.body["dispatch_id"][:64]
        audit_ledger.record_event(
            tenant_id=tenant.tenant_id,
            endpoint=request.url.path,
            reference_id=ref_id,
            decision="BLOCKED",
            http_status=422,
            redacted_types=[],
            summary=reasons[:280],
        )

    safe_errors = jsonable_encoder(
        exc.errors(),
        custom_encoder={BaseException: str},
    )
    return JSONResponse(status_code=422, content={"detail": safe_errors})


# --- Vector 1, 2 & 3 Guard Logic ---

INJECTION_SIGNATURES = [
    r"(?i)(?:ignore|disregard|forget|override)\s+(?:\w+\s+){0,4}(?:previous|prior|above|system|all)\s+(?:\w+\s+){0,2}(?:instructions?|rules?|directives?|policies|policy|constraints?)",
    r"(?i)(?:reveal|print|dump|leak)\s+(?:\w+\s+){0,3}(?:system\s+prompt|hidden\s+(?:rules?|policy|instructions?)|developer\s+message)",
    r"(?i)bypass\s+(?:privacy\s+policy|safety|guardrails?|audit)",
    r"(?i)export\s+all\s+customer\s+records",
    r"(?i)(?:^|\n)\s*(?:system|developer)\s*:\s*.*(?:unrestricted|override|comply|ignore|reveal|disable)",
    r"(?i)\b(?:jailbreak|developer\s+mode|do\s+anything\s+now)\b",
]

SOCIAL_ENGINEERING_PII_SIGNATURES = [
    r"(?i)(system\s+administrator|security\s+auditor|compliance\s+officer).*?(export|list|reveal|bypass).*?(customer|ssn|user|privacy)",
]

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
SECRET_RE = re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b")
PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> str:
    """Neutralizes spreadsheet formula injection (DDE/CSV injection) on export."""
    text = str(value)
    if text and text[0] in CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def contains_injection(text: str) -> bool:
    expanded = normalize_text_for_inspection(text)
    return any(re.search(sig, expanded) for sig in INJECTION_SIGNATURES)


def is_social_engineering_pii_pretext(text: str) -> bool:
    expanded = normalize_text_for_inspection(text)
    return any(re.search(sig, expanded) for sig in SOCIAL_ENGINEERING_PII_SIGNATURES)


def luhn_valid(digits: str) -> bool:
    nums = [int(d) for d in digits]
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def redact_sensitive_entities(text: str) -> tuple[str, List[str]]:
    redacted_types: List[str] = []
    out = text
    if SSN_RE.search(out):
        redacted_types.append("SSN")
        out = SSN_RE.sub("[REDACTED_SSN]", out)
    if SECRET_RE.search(out):
        redacted_types.append("API_SECRET")
        out = SECRET_RE.sub("[REDACTED_SECRET]", out)

    def _pan_sub(match: re.Match) -> str:
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            if "PAN" not in redacted_types:
                redacted_types.append("PAN")
            return "[REDACTED_PAN]"
        return raw

    out = PAN_RE.sub(_pan_sub, out)
    return out, redacted_types


def is_anomalous_flood(text: str) -> Optional[str]:
    if re.search(r"(.)\1{19,}", text) or re.search(r"\b(\w+)(\s+\1){9,}\b", text, re.IGNORECASE):
        return "anomaly_repeating_chars"
    if len(text) >= 40:
        freq = {ch: text.count(ch) / len(text) for ch in set(text)}
        entropy = -sum(p * math.log2(p) for p in freq.values())
        if entropy > 4.7 and " " not in text.strip():
            return "anomaly_high_entropy"
    return None


class MessageTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=4000)


class GuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(..., min_length=1, max_length=4000)
    messages: Optional[List[MessageTurn]] = None


class GuardResponse(BaseModel):
    status: Literal["ALLOWED", "REDACTED"]
    tenant_id: str
    sanitized_prompt: str
    sanitized_messages: Optional[List[MessageTurn]] = None
    redacted_entities: List[str]
    framework_version: str = FRAMEWORK_VERSION
    ledger_entry_hash: str


# --- Evidence Chain Schemas ---

class EvidenceTestResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    test: str = Field(..., min_length=1, max_length=200)
    passed: bool


class EvidenceCounterexample(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str = Field(..., min_length=1, max_length=2000)
    resolved: bool


class EvidenceRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: str = Field(..., min_length=1, max_length=4000)
    source_uri: str = Field(..., min_length=1, max_length=2000)
    source_sha256: str = Field(..., pattern=r"^[0-9a-fA-F]{64}$")
    evidence_summary: str = Field(..., min_length=1, max_length=4000)
    evidence_type: str = Field(..., min_length=1, max_length=100)
    rule_id: str = Field(..., min_length=1, max_length=128)
    rule_version: str = Field(..., min_length=1, max_length=64)
    test_results: List[EvidenceTestResult] = Field(default_factory=list)
    counterexamples: List[EvidenceCounterexample] = Field(default_factory=list)


def _get_evidence_store() -> EvidenceChainStore:
    """Dynamically binds to audit_ledger.db_path so tests and Render /var/data stay in sync."""
    return EvidenceChainStore(audit_ledger.db_path)


# --- Portal, Health & Core Endpoints ---

@app.get("/", include_in_schema=False)
async def serve_web_portal():
    portal_path = Path(__file__).resolve().parent.parent / "static" / "index.html"
    return FileResponse(portal_path)


@app.get("/health")
async def health_check():
    stats = audit_ledger.get_summary_stats()
    return {
        "status": "healthy",
        "framework": "Lucid-Truth-Audit",
        "version": FRAMEWORK_VERSION,
        "ledger_records": stats["ledger_records"],
        "latest_hash_prefix": stats["latest_hash_prefix"],
        "vectors": ["vector1_injection", "vector2_pii", "vector3_resilience", "vector4_logistics"],
    }


def _inspect_text_or_block(text: str, tenant: TenantContext, context_label: str) -> None:
    if is_social_engineering_pii_pretext(text):
        logger.warning("security.input_blocked category=social_engineering_pii tenant=%s", tenant.tenant_id)
        audit_ledger.record_event(tenant.tenant_id, "/api/v1/guard", context_label, "BLOCKED", 422, [], "Social engineering PII pretext")
        raise HTTPException(status_code=422, detail="Blocked social engineering PII request.")

    if contains_injection(text):
        category = "multi_turn_role_spoof" if context_label != "PROMPT" else "prompt_injection"
        logger.warning("security.input_blocked category=%s tenant=%s", category, tenant.tenant_id)
        audit_ledger.record_event(tenant.tenant_id, "/api/v1/guard", context_label, "BLOCKED", 422, [], f"Blocked: {category}")
        raise HTTPException(status_code=422, detail=f"Blocked {category.replace('_', ' ')} attempt.")

    anomaly = is_anomalous_flood(text)
    if anomaly:
        logger.warning("security.input_blocked category=%s tenant=%s", anomaly, tenant.tenant_id)
        audit_ledger.record_event(tenant.tenant_id, "/api/v1/guard", context_label, "BLOCKED", 422, [], f"Blocked: {anomaly}")
        raise HTTPException(status_code=422, detail=f"Blocked anomalous input: {anomaly}")


@app.post("/api/v1/guard", response_model=GuardResponse)
async def guard_endpoint(
    payload: GuardRequest,
    tenant: TenantContext = Depends(authenticate_and_limit),
):
    _inspect_text_or_block(payload.prompt, tenant, "PROMPT")
    clean_prompt, all_entities = redact_sensitive_entities(payload.prompt)

    sanitized_turns: Optional[List[MessageTurn]] = None
    if payload.messages:
        sanitized_turns = []
        for idx, turn in enumerate(payload.messages):
            _inspect_text_or_block(turn.content, tenant, f"TURN_{idx}")
            clean_turn, turn_entities = redact_sensitive_entities(turn.content)
            for ent in turn_entities:
                if ent not in all_entities:
                    all_entities.append(ent)
            sanitized_turns.append(MessageTurn(role=turn.role, content=clean_turn))

    all_entities = sorted(set(all_entities))
    decision = "REDACTED" if all_entities else "ALLOWED"
    row = audit_ledger.record_event(
        tenant.tenant_id,
        "/api/v1/guard",
        "PROMPT",
        decision,
        200,
        all_entities,
        f"Prompt processed; redacted={all_entities or 'none'}",
    )
    return GuardResponse(
        status=decision,
        tenant_id=tenant.tenant_id,
        sanitized_prompt=clean_prompt,
        sanitized_messages=sanitized_turns,
        redacted_entities=all_entities,
        ledger_entry_hash=row["entry_hash"],
    )


# --- Tenant-Isolated Evidence Chain Endpoints ---

@app.post("/api/v1/evidence", status_code=status.HTTP_201_CREATED)
async def create_evidence_record(
    payload: EvidenceRecordRequest,
    tenant: TenantContext = Depends(authenticate_and_limit),
):
    store = _get_evidence_store()
    try:
        record = store.add(tenant.tenant_id, payload.model_dump())
    except DuplicateEvidenceError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return record


@app.get("/api/v1/evidence")
async def list_evidence_records(
    limit: int = 100,
    tenant: TenantContext = Depends(authenticate_and_limit),
):
    store = _get_evidence_store()
    return {
        "tenant_id": tenant.tenant_id,
        "records": store.list_records(tenant.tenant_id, limit=limit),
    }


@app.get("/api/v1/evidence/verify")
async def verify_evidence_chain(
    tenant: TenantContext = Depends(authenticate_and_limit),
):
    store = _get_evidence_store()
    result = store.verify(tenant.tenant_id)
    return {
        "tenant_id": tenant.tenant_id,
        **result,
    }


# --- Audit Ledger Endpoints ---

@app.get("/api/v1/audit/ledger")
async def get_tenant_ledger(
    limit: int = 100,
    tenant: TenantContext = Depends(authenticate_and_limit),
):
    return {
        "tenant_id": tenant.tenant_id,
        "chain_integrity": audit_ledger.verify_chain(),
        "events": audit_ledger.list_events(tenant.tenant_id, limit=limit),
    }


@app.get("/api/v1/audit/export.csv")
async def export_tenant_ledger_csv(
    tenant: TenantContext = Depends(authenticate_and_limit),
):
    events = audit_ledger.list_events(tenant.tenant_id, limit=500)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp_utc", "tenant_id", "endpoint", "reference_id", "decision", "http_status", "redacted_types", "summary", "entry_hash"])
    for ev in events:
        writer.writerow([
            ev["id"],
            sanitize_csv_cell(ev["timestamp_utc"]),
            sanitize_csv_cell(ev["tenant_id"]),
            sanitize_csv_cell(ev["endpoint"]),
            sanitize_csv_cell(ev["reference_id"]),
            sanitize_csv_cell(ev["decision"]),
            ev["http_status"],
            sanitize_csv_cell(";".join(ev["redacted_types"])),
            sanitize_csv_cell(ev["summary"]),
            sanitize_csv_cell(ev["entry_hash"]),
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="lucid_audit_{tenant.tenant_id}.csv"'},
    