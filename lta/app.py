"""Lucid-Truth-Audit Enterprise FastAPI Application (Hardened v2.4.1)."""

from __future__ import annotations

import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Literal, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from lta import __version__
from lta.audit_ledger import AuditLedger
from lta.config import Settings, TenantConfig
from lta.metrics import MetricsRegistry
from lta.policy_engine import PolicyEngine
from lta.providers import UpstreamProviderError, call_upstream
from lta.rate_limiter import SlidingWindowRateLimiter


MAX_BODY_BYTES = int(os.getenv("LTA_MAX_BODY_BYTES", str(256 * 1024)))


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(..., min_length=1, max_length=65536)

    @field_validator("content")
    @classmethod
    def _non_blank_content(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Message content cannot be blank or whitespace-only.")
        return v


class OpenAIChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: Optional[str] = None
    messages: List[ChatMessage] = Field(..., min_length=1, max_length=50)
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=32768)
    metadata: Optional[Dict[str, Any]] = None


class LegacyGuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_input: str = Field(..., min_length=1, max_length=65536)
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("model_input")
    @classmethod
    def _non_blank_input(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("model_input cannot be blank or whitespace-only.")
        return v


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    engine = PolicyEngine(cfg.policy_dir)
    ledger = AuditLedger(cfg.audit_db_url)
    limiter = SlidingWindowRateLimiter(redis_url=cfg.redis_url)
    metrics = MetricsRegistry()
    disable_docs = os.getenv("LTA_DISABLE_DOCS", "false").lower().strip() in (
        "1",
        "true",
        "yes",
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.http_client = httpx.AsyncClient(timeout=cfg.upstream_timeout_s)
        try:
            yield
        finally:
            await application.state.http_client.aclose()
            ledger.close()

    app = FastAPI(
        title="Lucid-Truth-Audit Enterprise Gateway",
        version=__version__,
        lifespan=lifespan,
        docs_url=None if disable_docs else "/docs",
        redoc_url=None if disable_docs else "/redoc",
        openapi_url=None if disable_docs else "/openapi.json",
        description=(
            "Drop-in OpenAI-compatible AI security, PII redaction, and regulatory "
            "compliance gateway with YAML policy packs and SHA-256 hash-chained "
            "audit logs."
        ),
    )
    app.state.settings = cfg
    app.state.engine = engine
    app.state.ledger = ledger
    app.state.limiter = limiter
    app.state.metrics = metrics
    app.state.http_client = None

    @app.middleware("http")
    async def security_and_body_limit_middleware(
        request: Request,
        call_next: Any,
    ) -> Response:
        req_id = (
            (request.headers.get("x-request-id") or "").strip()[:64]
            or str(uuid.uuid4())
        )
        sec_headers = {
            "X-Request-ID": req_id,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }

        content_length = request.headers.get("content-length")
        if (
            content_length
            and content_length.isdigit()
            and int(content_length) > MAX_BODY_BYTES
        ):
            return JSONResponse(
                status_code=413,
                content={
                    "detail": (
                        f"Payload Too Large: exceeds {MAX_BODY_BYTES} byte limit."
                    )
                },
                headers=sec_headers,
            )

        if request.method in ("POST", "PUT", "PATCH") and not (
            content_length and content_length.isdigit()
        ):
            chunks: List[bytes] = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": (
                                f"Payload Too Large: exceeds "
                                f"{MAX_BODY_BYTES} byte limit."
                            )
                        },
                        headers=sec_headers,
                    )
                chunks.append(chunk)
            request._body = b"".join(chunks)

        response = await call_next(request)
        for key, value in sec_headers.items():
            response.headers[key] = value
        return response

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
                detail=(
                    "Fail-closed configuration error: "
                    "no tenant API keys configured."
                ),
            )

        tenant = cfg.authenticate(raw_key)
        if not tenant:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Invalid or missing API key.",
            )

        allowed, remaining = limiter.check(
            tenant.tenant_id,
            tenant.rate_limit_rpm,
        )
        if not allowed:
            metrics.observe(
                policy_pack=tenant.policy_pack,
                http_status=429,
                latency_ms=0.1,
                vector="resilience.rate_limit_exceeded",
            )
            raise HTTPException(
                status_code=429,
                detail=(
                    "Too Many Requests: Tenant sliding-window "
                    "rate limit exceeded."
                ),
                headers={"X-RateLimit-Remaining": str(remaining)},
            )
        return tenant

    def require_admin(
        tenant: TenantConfig = Depends(authenticate_tenant),
    ) -> TenantConfig:
        if tenant.role != "admin":
            raise HTTPException(
                status_code=403,
                detail=(
                    "Forbidden: Admin role required for audit "
                    "administration endpoints."
                ),
            )
        return tenant

    @app.get("/health")
    @app.get("/healthz")
    async def healthz() -> Dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "policies_loaded": len(engine.packs),
        }

    @app.get("/readyz")
    async def readyz() -> Dict[str, Any]:
        db_ok = ledger.ping()
        if not db_ok or not cfg.tenants or not engine.packs:
            raise HTTPException(status_code=503, detail="Gateway not ready")
        return {
            "status": "ready",
            "database_ok": db_ok,
            "policies_loaded": len(engine.packs),
        }

    @app.get("/metrics")
    async def prometheus_metrics(
        _: TenantConfig = Depends(require_admin),
    ) -> Response:
        return Response(
            content=metrics.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/v1/policies")
    async def list_policies(
        tenant: TenantConfig = Depends(authenticate_tenant),
    ) -> Dict[str, Any]:
        return {
            "active_tenant": tenant.tenant_id,
            "active_policy": tenant.policy_pack,
            "available_policies": engine.list_packs(),
        }

    @app.get("/v1/audit/verify")
    async def verify_audit_chain(
        _: TenantConfig = Depends(require_admin),
    ) -> Dict[str, Any]:
        valid, total, broken_seq = ledger.verify_chain()
        return {
            "chain_valid": valid,
            "total_records": total,
            "first_broken_seq_id": broken_seq,
        }

    @app.get("/v1/audit/export
