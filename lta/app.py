"""Lucid-Truth-Audit Enterprise FastAPI Application (Hardened v2.2)."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
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
    messages: List[ChatMessage] = Field(..., min_length=1, max_length=50)
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

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
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
                detail="Forbidden: Admin role required for audit administration endpoints.",
            )
        return tenant

    @app.get("/healthz")
    async def healthz() -> Dict[str, Any]:
        return {"status": "ok", "version": __version__, "policies_loaded": len(engine.packs)}

    @app.get("/readyz")
    async def readyz() -> Dict[str, Any]:
        chain_ok, total, _ = ledger.verify_chain()
        if not chain_ok or not cfg.tenants or not engine.packs:
            raise HTTPException(status_code=503, detail="Gateway not ready")
        return {
            "status": "ready",
            "audit_chain_valid": chain_ok,
            "audit_records": total,
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

    @app.get("/v1/audit/export")
    async def export_audit_jsonl(
        tenant_id: Optional[str] = None,
        limit: int = 500,
        _: TenantConfig = Depends(require_admin),
    ) -> Response:
        body = ledger.export_jsonl(tenant_id=tenant_id, limit=min(max(limit, 1), 5000))
        return Response(content=body, media_type="application/x-ndjson")

    async def _run_pipeline(
        *,
        tenant: TenantConfig,
        endpoint: str,
        messages: List[Dict[str, str]],
        model: str,
        policy_override: Optional[str],
        provider_override: Optional[str],
        metadata: Optional[Dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()

        if (policy_override or provider_override) and tenant.role != "admin":
            latency_ms = (time.perf_counter() - t0) * 1000.0
            rec = ledger.record(
                tenant_id=tenant.tenant_id,
                endpoint=endpoint,
                policy_pack=tenant.policy_pack,
                provider=tenant.provider,
                action="BLOCK",
                http_status=403,
                vector="security.unauthorized_policy_override",
                redactions=[],
                raw_payload_for_digest=f"{policy_override}|{provider_override}",
                latency_ms=latency_ms,
            )
            metrics.observe(
                policy_pack=tenant.policy_pack,
                http_status=403,
                latency_ms=latency_ms,
                vector="security.unauthorized_policy_override",
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Forbidden: Only admin keys may override policy pack or upstream provider.",
                    "vector": "security.unauthorized_policy_override",
                    "audit_entry_hash": rec.entry_hash,
                },
            )

        policy_name = policy_override or tenant.policy_pack
        provider_name = provider_override or tenant.provider
        if policy_name not in engine.packs:
            raise HTTPException(
                status_code=400, detail=f"Unknown policy pack: '{policy_name}'"
            )

        for idx, msg in enumerate(messages):
            if msg["role"] == "system" and (idx > 0 or tenant.role != "admin"):
                latency_ms = (time.perf_counter() - t0) * 1000.0
                rec = ledger.record(
                    tenant_id=tenant.tenant_id,
                    endpoint=endpoint,
                    policy_pack=policy_name,
                    provider=provider_name,
                    action="BLOCK",
                    http_status=400,
                    vector="security.multi_turn_system_spoofing",
                    redactions=[],
                    raw_payload_for_digest=msg["content"],
                    latency_ms=latency_ms,
                )
                metrics.observe(
                    policy_pack=policy_name,
                    http_status=400,
                    latency_ms=latency_ms,
                    vector="security.multi_turn_system_spoofing",
                )
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "Blocked unauthorized system-role message",
                        "vector": "security.multi_turn_system_spoofing",
                        "audit_entry_hash": rec.entry_hash,
                    },
                )

        sanitized_messages: List[Dict[str, str]] = []
        all_redactions: List[str] = []
        non_system_contents = [
            m["content"] for m in messages if m["role"] in ("user", "assistant")
        ]
        combined_input_for_digest = "\n".join(m["content"] for m in messages)

        if len(non_system_contents) > 1:
            combined_res = engine.evaluate_input(
                " ".join(non_system_contents), policy_name=policy_name, metadata=metadata
            )
            if not combined_res.allowed:
                latency_ms = (time.perf_counter() - t0) * 1000.0
                rec = ledger.record(
                    tenant_id=tenant.tenant_id,
                    endpoint=endpoint,
                    policy_pack=policy_name,
                    provider=provider_name,
                    action="BLOCK",
                    http_status=combined_res.http_status,
                    vector=combined_res.vector,
                    redactions=[],
                    raw_payload_for_digest=combined_input_for_digest,
                    latency_ms=latency_ms,
                )
                metrics.observe(
                    policy_pack=policy_name,
                    http_status=combined_res.http_status,
                    latency_ms=latency_ms,
                    vector=combined_res.vector,
                )
                raise HTTPException(
                    status_code=combined_res.http_status,
                    detail={
                        "error": combined_res.reason,
                        "vector": combined_res.vector,
                        "policy_pack": policy_name,
                        "audit_entry_hash": rec.entry_hash,
                    },
                )

        for msg in messages:
            if msg["role"] in ("user", "assistant"):
                in_res = engine.evaluate_input(
                    msg["content"], policy_name=policy_name, metadata=metadata
                )
                if not in_res.allowed:
                    latency_ms = (time.perf_counter() - t0) * 1000.0
                    rec = ledger.record(
                        tenant_id=tenant.tenant_id,
                        endpoint=endpoint,
                        policy_pack=policy_name,
                        provider=provider_name,
                        action="BLOCK",
                        http_status=in_res.http_status,
                        vector=in_res.vector,
                        redactions=[],
                        raw_payload_for_digest=combined_input_for_digest,
                        latency_ms=latency_ms,
                    )
                    metrics.observe(
                        policy_pack=policy_name,
                        http_status=in_res.http_status,
                        latency_ms=latency_ms,
                        vector=in_res.vector,
                    )
                    raise HTTPException(
                        status_code=in_res.http_status,
                        detail={
                            "error": in_res.reason,
                            "vector": in_res.vector,
                            "policy_pack": policy_name,
                            "audit_entry_hash": rec.entry_hash,
                        },
                    )
                all_redactions.extend(in_res.redactions)
                sanitized_messages.append(
                    {"role": msg["role"], "content": in_res.sanitized_text}
                )
            else:
                sanitized_messages.append(msg)

        try:
            upstream = await call_upstream(
                provider=provider_name,
                model=model,
                messages=sanitized_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout_s=cfg.upstream_timeout_s,
            )
        except UpstreamProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        out_res = engine.evaluate_output(upstream.content, policy_name=policy_name)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        if not out_res.allowed:
            rec = ledger.record(
                tenant_id=tenant.tenant_id,
                endpoint=endpoint,
                policy_pack=policy_name,
                provider=provider_name,
                action="BLOCK",
                http_status=out_res.http_status,
                vector=out_res.vector,
                redactions=sorted(set(all_redactions)),
                raw_payload_for_digest=combined_input_for_digest,
                latency_ms=latency_ms,
            )
            metrics.observe(
                policy_pack=policy_name,
                http_status=out_res.http_status,
                latency_ms=latency_ms,
                vector=out_res.vector,
            )
            raise HTTPException(
                status_code=out_res.http_status,
                detail={
                    "error": out_res.reason,
                    "vector": out_res.vector,
                    "policy_pack": policy_name,
                    "audit_entry_hash": rec.entry_hash,
                },
            )

        all_redactions.extend(out_res.redactions)
        unique_redactions = sorted(set(all_redactions))
        final_action = "ALLOW_REDACTED" if unique_redactions else "ALLOW"
        rec = ledger.record(
            tenant_id=tenant.tenant_id,
            endpoint=endpoint,
            policy_pack=policy_name,
            provider=provider_name,
            action=final_action,
            http_status=200,
            vector=None,
            redactions=unique_redactions,
            raw_payload_for_digest=combined_input_for_digest,
            latency_ms=latency_ms,
        )
        metrics.observe(
            policy_pack=policy_name,
            http_status=200,
