import os
import re
import hmac
import time
import math
import base64
import logging
import unicodedata
from collections import defaultdict
from typing import List, Optional, Literal
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.schemas.logistics_guard import router as logistics_router

logger = logging.getLogger("lucid_truth_audit")

app = FastAPI(
    title="Lucid-Truth-Audit",
    version="1.0.0",
    description="Deterministic AI Governance, Prompt Injection, PII Redaction, and Logistics Compliance Guardrails",
)

app.include_router(logistics_router)

# --- Vector 1: Obfuscation & Prompt Injection Normalization ---

INJECTION_SIGNATURES = [
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"(?i)reveal\s+(your\s+)?system\s+prompt",
    r"(?i)bypass\s+privacy\s+policy",
    r"(?i)export\s+all\s+customer\s+records",
]


def normalize_obfuscated_text(text: str) -> str:
    # Strip zero-width chars
    stripped = re.sub(r"[\u200b-\u200f\ufeff]", "", text)
    # Normalize Cyrillic homoglyphs
    homoglyphs = str.maketrans({"о": "o", "е": "e", "а": "a", "і": "i", "р": "p", "с": "c", "у": "y", "х": "x"})
    normalized = unicodedata.normalize("NFKC", stripped).translate(homoglyphs)
    candidates = [normalized]
    # Attempt base64 / hex decode inspection
    compact = normalized.strip()
    if len(compact) >= 12 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            candidates.append(base64.b64decode(compact).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    if len(compact) >= 16 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try:
            candidates.append(bytes.fromhex(compact).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return " ".join(candidates)


def contains_injection(text: str) -> bool:
    expanded = normalize_obfuscated_text(text)
    return any(re.search(sig, expanded) for sig in INJECTION_SIGNATURES)


# --- Vector 2: PII & Secret Scrubbing ---

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
SECRET_RE = re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b")
PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


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
    redacted_types = []
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


# --- Vector 3: Sliding-Window Rate Limiter & Flood Anomaly Detector ---

RATE_BUCKETS: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX = 10
RATE_WINDOW_SEC = 60.0


def check_rate_limit(api_key: str) -> bool:
    now = time.time()
    window_start = now - RATE_WINDOW_SEC
    RATE_BUCKETS[api_key] = [t for t in RATE_BUCKETS[api_key] if t >= window_start]
    if len(RATE_BUCKETS[api_key]) >= RATE_LIMIT_MAX:
        return False
    RATE_BUCKETS[api_key].append(now)
    return True


def is_anomalous_flood(text: str) -> Optional[str]:
    if re.search(r"(.)\1{19,}", text) or re.search(r"\b(\w+)(\s+\1){9,}\b", text, re.IGNORECASE):
        return "anomaly_repeating_chars"
    if len(text) >= 40:
        freq = {ch: text.count(ch) / len(text) for ch in set(text)}
        entropy = -sum(p * math.log2(p) for p in freq.values())
        if entropy > 4.7 and " " not in text.strip():
            return "anomaly_high_entropy"
    return None


# --- Schemas & Auth ---

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
    sanitized_prompt: str
    redacted_entities: List[str]
    framework_version: str = "1.0.0"


def verify_api_key(x_api_key: Optional[str]) -> str:
    expected = os.getenv("LUCID_AUDIT_API_KEY", "")
    if not expected:
        logger.error("security.configuration_error missing_api_key_configuration")
        raise HTTPException(status_code=503, detail="Server authentication secret not configured.")
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        logger.warning("security.authentication_rejected")
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "framework": "Lucid-Truth-Audit",
        "version": "1.0.0",
        "vectors": ["vector1_injection", "vector2_pii", "vector3_resilience", "vector4_logistics"],
    }


@app.post("/api/v1/guard", response_model=GuardResponse)
async def guard_endpoint(payload: GuardRequest, x_api_key: Optional[str] = Header(default=None)):
    key = verify_api_key(x_api_key)
    if not check_rate_limit(key):
        logger.warning("security.rate_limit_exceeded")
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    anomaly = is_anomalous_flood(payload.prompt)
    if anomaly:
        logger.warning(f"security.input_blocked category={anomaly}")
        raise HTTPException(status_code=422, detail=f"Blocked anomalous input: {anomaly}")

    if contains_injection(payload.prompt):
        logger.warning("security.input_blocked category=prompt_injection")
        raise HTTPException(status_code=422, detail="Blocked prompt injection attempt.")

    if payload.messages:
        for turn in payload.messages:
            if contains_injection(turn.content):
                logger.warning("security.input_blocked category=multi_turn_role_spoof")
                raise HTTPException(status_code=422, detail="Blocked multi-turn spoofing attempt.")

    clean_prompt, entities = redact_sensitive_entities(payload.prompt)
    return GuardResponse(
        status="REDACTED" if entities else "ALLOWED",
        sanitized_prompt=clean_prompt,
        redacted_entities=entities,
    )
