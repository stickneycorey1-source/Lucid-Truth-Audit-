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
from pydantic import BaseModel, Field, ConfigDict, field_validator

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
from app.api.shadow import router as shadow_router

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
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    )

app.include_router(logistics_router)
app.include_router(shadow_router)


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
            "connect-src 'self'; frame-
