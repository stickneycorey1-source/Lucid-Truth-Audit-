"""Lucid-Truth-Audit Enterprise FastAPI Application (Hardened v2.1)."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from lta import __version__
from lta.audit_ledger import AuditLedger
from lta.config import Settings, TenantConfig
from lta.metrics import MetricsRegistry
from lta.policy_engine import PolicyEngine
from lta.providers import UpstreamProviderError, call_upstream
from lta.rate_limiter import SlidingWindowRateLimiter


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(..., min_length=1, max_length=65536)


class OpenAIChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: Optional[str] = None
    messages: List[ChatMessage] = Field(..., min_length=1)
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=32768)
    metadata: Optional[Dict[str, Any]] = None


class LegacyGuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_input: str = Field(..., min_length=1, max_length=65536)
    metadata: Optional[Dict[str, Any]] = None


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    engine = PolicyEngine(cfg.policy_dir)
    ledger = AuditLedger(cfg.audit_db_url)
    limiter = SlidingWindowRateLimiter(redis_url=cfg.redis_url)
    metrics = MetricsRegistry()

    app = FastAPI(
        title="Lucid-Truth-Audit Enterprise Gateway",
        version=__version__,
        description=(
            "Drop-in OpenAI-compatible AI security, PII redaction, and regulatory "
            "compliance gateway with YAML policy packs and SHA-256 hash-chained audit logs."
        ),
    )
    app.state.settings = cfg
    app.state.engine = engine
    app.state.ledger = ledger
    app.state.limiter = limiter
    app.state.metrics = metrics

    def _extract_key(
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None),
    ) -> Optional[str]:
        if x_api_key:
            return x_api_key.strip()
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return None

    def authenticate_tenant(
        raw_key: Optional[str] = Depends(_extract_key),
    ) -> TenantConfig:
        if not cfg.tenants:
            raise HTTPException(
                status_code=500,
                detail="Fail-closed configuration error: no tenant API keys configured.",
            )
        tenant = cfg.authenticate(raw_key)
        if not tenant:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Invalid or missing API key.",
            )
        allowed, remaining = limiter.check(tenant.tenant_id, tenant.rate_limit_rpm)
        if not allowed:
            metrics.observe(
                tenant_id=tenant.tenant_id,
                policy_pack=tenant.policy_pack,
                http_status=429,
                latency_ms=0.1,
                vector="resilience.rate_limit_exceeded",
            )
            raise HTTPException(
                status_code=429,
                detail="Too Many Requests: Tenant sliding-window rate limit exceeded.",
                headers={"X-RateLimit-Remaining": str(remaining)},
            )
        return tenant

    def require_admin(tenant: TenantConfig = Depends(authenticate_tenant)) -> TenantConfig:
        if tenant.role != "admin":
            raise HTTPException(
                status_code=403,
                detail="
