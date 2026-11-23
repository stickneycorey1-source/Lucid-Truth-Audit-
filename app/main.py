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

# Configurable CORS allowlist for external portals (e.g., Vercel