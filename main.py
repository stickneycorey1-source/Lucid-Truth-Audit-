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
from app.security import TenantContext, authenticate_and_limit, resolve_valid_tenant
from app.ledger import audit_ledger
from app.schemas.logistics_guard import router as logistics_router

logger = logging.getLogger("lucid_truth_audit")

app = FastAPI(
    title="Lucid-Truth-Audit",
    version="2.0.1",
    description="Production Deterministic AI Security, PII Redaction, and FMCSA Fleet Compliance Engine",
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
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
    )
    return response


# --- Global Validation Error Handler (Authenticated-Only 422 Tenant Ledger Logging) ---

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/api/v1/guard"):
        tenant = resolve_valid_tenant(request.headers.get("X-API-Key"))
        if tenant is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid, expired, or missing API key."},
            )
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
    
