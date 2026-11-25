"""Lucid-Truth-Audit (v2.4.1) FastAPI enterprise AI security & compliance gateway."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from lta.audit_ledger import AuditLedger
from lta.config import Settings, TenantConfig
from lta.metrics import MetricsRegistry
from lta.policy_engine import PolicyEngine
from lta.providers import UpstreamProviderError, call_upstream
from lta.rate_limiter import SlidingWindowRateLimiter

logger = logging.getLogger("lta.app")

MAX_BODY_BYTES = int(os.getenv("LTA_MAX_BODY_BYTES", str(256 * 1024)))
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(..., min_length=1)


class OpenAIChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = Field(default="gpt-4o-mini", min_length=1)
    messages: List[ChatMessage] = Field(..., min_length=1, max_length=50)
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=128000)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in value.items():
            if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
                raise ValueError(f"Non-finite float in metadata key '{k}'")
        return value


class LegacyGuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_input: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in value.items():
            if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
                raise ValueError(f"Non-finite float in metadata key '{k}'")
        return value


class ShadowIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(..., min_length=1)
    request_id: Optional[str] = Field(default=None, max_length=128)
    model_target: Optional[str] = Field(default=None, max_length=128)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in value.items():
            if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
                raise ValueError(f"Non-finite float in metadata key '{k}'")
        return value


@dataclass
class GatewayRuntime:
    settings: Settings
    policy_engine: PolicyEngine
    audit_ledger: AuditLedger
    rate_limiter: SlidingWindowRateLimiter
    metrics: MetricsRegistry


def _extract_api_key(
    x_api_key: Optional[str],
    authorization: Optional[str],
) -> Optional[str]:
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    if authorization and authorization.strip():
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()
    return None


def _resolve_request_id(raw_id: Optional[str]) -> str:
    if raw_id and _REQUEST_ID_RE.match(raw_id.strip()):
        return raw_id.strip()
    return str(uuid.uuid4())


def _apply_security_headers(response: Response, request_id: str) -> None:
    response.headers["X-Request-ID"] = request_id
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"


def _blocked_detail(vector: str, message: str) -> Dict[str, str]:
    return {"vector": vector, "message": message}


@asynccontextmanager
async def _app_lifespan(fastapi_app: FastAPI):
    runtime: Optional[GatewayRuntime] = getattr(fastapi_app.state, "lta_runtime", None)
    logger.info("Lucid-Truth-Audit startup complete")
    try:
        yield
    finally:
        if runtime is not None:
            try:
                runtime.audit_ledger.close()
            except Exception as exc:
                logger.warning("Error closing audit ledger during shutdown: %s", exc)
        logger.info("Lucid-Truth-Audit shutdown complete")


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    policy_engine = PolicyEngine(cfg.policy_dir)
    audit_ledger = AuditLedger(cfg.audit_db_url)
    rate_limiter = SlidingWindowRateLimiter(redis_url=cfg.redis_url)
    metrics = MetricsRegistry()
    runtime = GatewayRuntime(
        settings=cfg,
        policy_engine=policy_engine,
        audit_ledger=audit_ledger,
        rate_limiter=rate_limiter,
        metrics=metrics,
    )

    disable_docs = os.getenv("LTA_DISABLE_DOCS", "false").lower().strip() in ("1", "true", "yes")
    docs_url = None if disable_docs else "/docs"
    redoc_url = None if disable_docs else "/redoc"
    openapi_url = None if disable_docs else "/openapi.json"

    fastapi_app = FastAPI(
        title="Lucid-Truth-Audit Gateway",
        version="2.4.1",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=_app_lifespan,
    )
    fastapi_app.state.lta_runtime = runtime
    fastapi_app.state.audit_ledger = audit_ledger
    fastapi_app.state.ledger = audit_ledger
    fastapi_app.state.rate_limiter = rate_limiter

    @fastapi_app.middleware("http")
    async def _ingress_middleware(request: Request, call_next):
        req_id = _resolve_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = req_id

        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_BODY_BYTES:
                    resp = JSONResponse(
                        status_code=413,
                        content={
                            "detail": _blocked_detail(
                                "ingress.body_too_large",
                                "Request body exceeds maximum allowed size",
                            )
                        },
                    )
                    _apply_security_headers(resp, req_id)
                    return resp
            except ValueError:
                pass

        body_bytes = await request.body()
        if len(body_bytes) > MAX_BODY_BYTES:
            resp = JSONResponse(
                status_code=413,
                content={
                    "detail": _blocked_detail(
                        "ingress.body_too_large",
                        "Request body exceeds maximum allowed size",
                    )
                },
            )
            _apply_security_headers(resp, req_id)
            return resp

        response = await call_next(request)
        _apply_security_headers(response, req_id)
        return response

    async def _authenticate_tenant(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
    ) -> TenantConfig:
        if not cfg.tenants:
            raise HTTPException(
                status_code=500,
                detail=_blocked_detail("auth.unconfigured", "No tenant credentials configured on gateway"),
            )
        token = _extract_api_key(x_api_key, authorization)
        if not token:
            raise HTTPException(
                status_code=403,
                detail=_blocked_detail("auth.missing_credentials", "Missing API credentials"),
            )
        tenant = cfg.authenticate(token)
        if tenant is None:
            raise HTTPException(
                status_code=403,
                detail=_blocked_detail("auth.invalid_credentials", "Invalid API credentials"),
            )

        allowed, remaining = rate_limiter.check(tenant.tenant_id, tenant.rate_limit_rpm)
        request.state.rate_limit_remaining = remaining
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=_blocked_detail("resilience.rate_limit_exceeded", "Tenant rate limit exceeded"),
                headers={"X-RateLimit-Remaining": str(max(0, remaining))},
            )
        return tenant

    async def _authenticate_shadow(
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
    ) -> str:
        token = _extract_api_key(x_api_key, authorization)
        if not token:
            raise HTTPException(
                status_code=401,
                detail=_blocked_detail("auth.missing_credentials", "Missing shadow ingest credentials"),
            )
        shadow_key = os.getenv("LTA_SHADOW_KEY", "").strip()
        if shadow_key:
            if hmac.compare_digest(token, shadow_key):
                return "shadow_ingest"
            raise HTTPException(
                status_code=403,
                detail=_blocked_detail("auth.invalid_credentials", "Invalid shadow ingest credentials"),
            )
        tenant = cfg.authenticate(token)
        if tenant is None:
            raise HTTPException(
                status_code=403,
                detail=_blocked_detail("auth.invalid_credentials", "Invalid shadow ingest credentials"),
            )
        return tenant.tenant_id

    async def _require_admin(tenant: TenantConfig = Depends(_authenticate_tenant)) -> TenantConfig:
        if tenant.role.lower() != "admin":
            raise HTTPException(
                status_code=403,
                detail=_blocked_detail("auth.admin_required", "Admin role required"),
            )
        return tenant

    async def _run_pipeline(
        *,
        request: Request,
        response: Response,
        tenant: TenantConfig,
        endpoint: str,
        messages: List[Dict[str, str]],
        model: str,
        temperature: Optional[float],
        max_tokens: Optional[int],
        metadata: Dict[str, Any],
        x_lta_policy: Optional[str],
        x_lta_provider: Optional[str],
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        is_admin = tenant.role.lower() == "admin"

        if (x_lta_policy or x_lta_provider) and not is_admin:
            latency_ms = (time.perf_counter() - started) * 1000.0
            vector = "security.unauthorized_policy_override"
            msg = "Policy or provider overrides require admin privileges"
            audit_ledger.record(
                tenant_id=tenant.tenant_id,
                endpoint=endpoint,
                policy_pack=tenant.policy_pack,
                provider=tenant.provider,
                action="BLOCK",
                http_status=403,
                vector=vector,
                redactions=[],
                raw_payload_for_digest="\n".join(m["content"] for m in messages),
                latency_ms=latency_ms,
            )
            metrics.observe(
                policy_pack=tenant.policy_pack,
                http_status=403,
                latency_ms=latency_ms,
                vector=vector,
            )
            raise HTTPException(status_code=403, detail=_blocked_detail(vector, msg))

        policy_name = x_lta_policy.strip() if (is_admin and x_lta_policy) else tenant.policy_pack
        provider_name = (
            x_lta_provider.strip() if (is_admin and x_lta_provider) else tenant.provider
        )

        try:
            policy_engine.get_pack(policy_name)
        except KeyError as exc:
            raise HTTPException(
                status_code=400,
                detail=_blocked_detail("policy.unknown_pack", str(exc)),
            ) from exc

        for idx, msg in enumerate(messages):
            if msg["role"] == "system" and (idx > 0 or not is_admin):
                latency_ms = (time.perf_counter() - started) * 1000.0
                vector = "security.multi_turn_system_spoofing"
                reason = "Unauthorized or misplaced system role message blocked by policy"
                audit_ledger.record(
                    tenant_id=tenant.tenant_id,
                    endpoint=endpoint,
                    policy_pack=policy_name,
                    provider=provider_name,
                    action="BLOCK",
                    http_status=400,
                    vector=vector,
                    redactions=[],
                    raw_payload_for_digest=msg["content"],
                    latency_ms=latency_ms,
                )
                metrics.observe(
                    policy_pack=policy_name,
                    http_status=400,
                    latency_ms=latency_ms,
                    vector=vector,
                )
                raise HTTPException(status_code=400, detail=_blocked_detail(vector, reason))

        non_system_turns = [m["content"] for m in messages if m["role"] != "system"]
        scan_targets: List[Tuple[str, Optional[Dict[str, Any]]]] = [
            (m["content"], metadata if m["role"] == "user" else None) for m in messages
        ]
        if len(non_system_turns) > 1:
            scan_targets.append(("\n".join(non_system_turns), metadata))

        for target_text, target_meta in scan_targets:
            probe_eval = policy_engine.evaluate_input(
                text=target_text,
                policy_name=policy_name,
                metadata=target_meta,
            )
            if not probe_eval.allowed:
                latency_ms = (time.perf_counter() - started) * 1000.0
                vector = probe_eval.vector or "policy.input_blocked"
                reason = probe_eval.reason or "Request blocked by security policy"
                audit_ledger.record(
                    tenant_id=tenant.tenant_id,
                    endpoint=endpoint,
                    policy_pack=policy_name,
                    provider=provider_name,
                    action="BLOCK",
                    http_status=probe_eval.http_status,
                    vector=vector,
                    redactions=probe_eval.redactions,
                    raw_payload_for_digest="\n".join(m["content"] for m in messages),
                    latency_ms=latency_ms,
                )
                metrics.observe(
                    policy_pack=policy_name,
                    http_status=probe_eval.http_status,
                    latency_ms=latency_ms,
                    vector=vector,
                )
                raise HTTPException(
                    status_code=probe_eval.http_status,
                    detail=_blocked_detail(vector, reason),
                )

        sanitized_messages: List[Dict[str, str]] = []
        input_redactions: List[str] = []
        for msg in messages:
            turn_eval = policy_engine.evaluate_input(
                text=msg["content"],
                policy_name=policy_name,
                metadata=metadata if msg["role"] == "user" else None,
            )
            sanitized_messages.append(
                {
                    "role": msg["role"],
                    "content": turn_eval.sanitized_text or msg["content"],
                }
            )
            input_redactions.extend(turn_eval.redactions)

        try:
            upstream_resp = await call_upstream(
                provider=provider_name,
                model=model,
                messages=sanitized_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout_s=cfg.upstream_timeout_s,
            )
        except UpstreamProviderError as exc:
            latency_ms = (time.perf_counter() - started) * 1000.0
            vector = "upstream.provider_error"
            reason = str(exc)
            audit_ledger.record(
                tenant_id=tenant.tenant_id,
                endpoint=endpoint,
                policy_pack=policy_name,
                provider=provider_name,
                action="BLOCK",
                http_status=502,
                vector=vector,
                redactions=sorted(set(input_redactions)),
                raw_payload_for_digest="\n".join(m["content"] for m in sanitized_messages),
                latency_ms=latency_ms,
            )
            metrics.observe(
                policy_pack=policy_name,
                http_status=502,
                latency_ms=latency_ms,
                vector=vector,
            )
            raise HTTPException(status_code=502, detail=_blocked_detail(vector, reason)) from exc

        output_eval = policy_engine.evaluate_output(
            text=upstream_resp.content,
            policy_name=policy_name,
        )
        if not output_eval.allowed:
            latency_ms = (time.perf_counter() - started) * 1000.0
            vector = output_eval.vector or "policy.output_blocked"
            reason = output_eval.reason or "Response blocked by output policy"
            audit_ledger.record(
                tenant_id=tenant.tenant_id,
                endpoint=endpoint,
                policy_pack=policy_name,
                provider=provider_name,
                action="BLOCK",
                http_status=output_eval.http_status,
                vector=vector,
                redactions=sorted(set(input_redactions + output_eval.redactions)),
                raw_payload_for_digest=upstream_resp.content,
                latency_ms=latency_ms,
            )
            metrics.observe(
                policy_pack=policy_name,
                http_status=output_eval.http_status,
                latency_ms=latency_ms,
                vector=vector,
            )
            raise HTTPException(
                status_code=output_eval.http_status,
                detail=_blocked_detail(vector, reason),
            )

        final_content = output_eval.sanitized_text or upstream_resp.content
        all_redactions = sorted(set(input_redactions + output_eval.redactions))
        final_action = "ALLOW_REDACTED" if all_redactions else "ALLOW"
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)

        audit_rec = audit_ledger.record(
            tenant_id=tenant.tenant_id,
            endpoint=endpoint,
            policy_pack=policy_name,
            provider=upstream_resp.provider,
            action=final_action,
            http_status=200,
            vector=None,
            redactions=all_redactions,
            raw_payload_for_digest=final_content,
            latency_ms=latency_ms,
        )
        metrics.observe(
            policy_pack=policy_name,
            http_status=200,
            latency_ms=latency_ms,
            vector=None,
        )

        rem = getattr(request.state, "rate_limit_remaining", None)
        if rem is not None:
            response.headers["X-RateLimit-Remaining"] = str(max(0, rem))

        lta_audit_meta = {
            "seq_id": audit_rec.seq_id,
            "entry_hash": audit_rec.entry_hash,
            "payload_sha256": audit_rec.payload_sha256,
            "policy_pack": policy_name,
            "action": final_action,
            "redactions": all_redactions,
            "latency_ms": latency_ms,
        }

        return {
            "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": upstream_resp.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": final_content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": upstream_resp.prompt_tokens,
                "completion_tokens": upstream_resp.completion_tokens,
                "total_tokens": upstream_resp.prompt_tokens + upstream_resp.completion_tokens,
            },
            "content": final_content,
            "action": final_action,
            "redactions": all_redactions,
            "policy_pack": policy_name,
            "audit_entry_hash": audit_rec.entry_hash,
            "audit_seq_id": audit_rec.seq_id,
            "latency_ms": latency_ms,
            "lta_audit": lta_audit_meta,
        }

    @fastapi_app.get("/health")
    @fastapi_app.get("/healthz")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "version": "2.4.0",
            "policies_loaded": len(policy_engine.list_packs()),
        }

    @fastapi_app.get("/readyz")
    async def readyz() -> JSONResponse:
        db_ok = audit_ledger.ping()
        policies_ok = len(policy_engine.list_packs()) > 0
        if not db_ok or not policies_ok:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "db_ok": db_ok,
                    "database_ok": db_ok,
                    "policies_ok": policies_ok,
                },
            )
        return JSONResponse(
            status_code=200,
            content={
                "status": "ready",
                "db_ok": True,
                "database_ok": True,
                "policies_ok": True,
                "tenants_configured": len(cfg.tenants),
            },
        )

    @fastapi_app.get("/v1/policies")
    async def list_policies(
        tenant: TenantConfig = Depends(_authenticate_tenant),
    ) -> Dict[str, Any]:
        return {
            "active_tenant": tenant.tenant_id,
            "active_policy": tenant.policy_pack,
            "available_policies": policy_engine.list_packs(),
        }

    @fastapi_app.post("/v1/chat/completions")
    async def chat_completions(
        payload: OpenAIChatCompletionRequest,
        request: Request,
        response: Response,
        tenant: TenantConfig = Depends(_authenticate_tenant),
        x_lta_policy: Optional[str] = Header(default=None, alias="X-LTA-Policy"),
        x_lta_provider: Optional[str] = Header(default=None, alias="X-LTA-Provider"),
    ) -> Dict[str, Any]:
        msgs = [{"role": m.role, "content": m.content} for m in payload.messages]
        return await _run_pipeline(
            request=request,
            response=response,
            tenant=tenant,
            endpoint="/v1/chat/completions",
            messages=msgs,
            model=payload.model,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            metadata=payload.metadata,
            x_lta_policy=x_lta_policy,
            x_lta_provider=x_lta_provider,
        )

    @fastapi_app.post("/api/v1/guard")
    async def legacy_guard(
        payload: LegacyGuardRequest,
        request: Request,
        response: Response,
        tenant: TenantConfig = Depends(_authenticate_tenant),
        x_lta_policy: Optional[str] = Header(default=None, alias="X-LTA-Policy"),
        x_lta_provider: Optional[str] = Header(default=None, alias="X-LTA-Provider"),
    ) -> Dict[str, Any]:
        msgs = [{"role": "user", "content": payload.model_input}]
        result = await _run_pipeline(
            request=request,
            response=response,
            tenant=tenant,
            endpoint="/api/v1/guard",
            messages=msgs,
            model=tenant.upstream_model,
            temperature=None,
            max_tokens=None,
            metadata=payload.metadata,
            x_lta_policy=x_lta_policy,
            x_lta_provider=x_lta_provider,
        )
        return {
            "status": "success",
            "allowed": True,
            **result,
        }

    @fastapi_app.post("/v1/shadow/ingest", status_code=status.HTTP_202_ACCEPTED)
    async def shadow_ingest(
        payload: ShadowIngestRequest,
        request: Request,
        shadow_actor: str = Depends(_authenticate_shadow),
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        policy_name = (
            "general_enterprise"
            if "general_enterprise" in policy_engine.packs
            else (
                next(iter(policy_engine.packs))
                if policy_engine.packs
                else "general_enterprise"
            )
        )

        input_sha256 = hashlib.sha256(payload.prompt.encode("utf-8")).hexdigest()
        eval_res = policy_engine.evaluate_input(
            text=payload.prompt,
            policy_name=policy_name,
            metadata=payload.metadata,
        )
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        action = "BLOCK" if not eval_res.allowed else eval_res.action

        # Zero-retention: pass only input_sha256 to ledger; never store or return raw prompt
        audit_rec = audit_ledger.record(
            tenant_id=shadow_actor,
            endpoint="/v1/shadow/ingest",
            policy_pack=policy_name,
            provider="shadow",
            action=action,
            http_status=202,
            vector=eval_res.vector,
            redactions=eval_res.redactions,
            raw_payload_for_digest=input_sha256,
            latency_ms=latency_ms,
        )
        metrics.observe(
            policy_pack=policy_name,
            http_status=202,
            latency_ms=latency_ms,
            vector=eval_res.vector,
        )

        audit_id = f"shd-{audit_rec.seq_id}-{input_sha256[:12]}"
        return {
            "status": "accepted",
            "audit_id": audit_id,
            "seq_id": audit_rec.seq_id,
            "entry_hash": audit_rec.entry_hash,
            "input_sha256": input_sha256,
            "request_id": payload.request_id or getattr(request.state, "request_id", None),
            "model_target": payload.model_target,
            "policy_pack": policy_name,
            "zero_retention": True,
        }

    @fastapi_app.get("/v1/audit/verify")
    async def audit_verify(
        _: TenantConfig = Depends(_require_admin),
    ) -> Dict[str, Any]:
        valid, total_records, first_broken_seq_id = audit_ledger.verify_chain()
        return {
            "chain_valid": valid,
            "total_records": total_records,
            "first_broken_seq_id": first_broken_seq_id,
        }

    @fastapi_app.get("/v1/audit/export")
    async def audit_export(
        tenant_id: Optional[str] = Query(default=None),
        limit: int = Query(default=500, ge=1, le=5000),
        _: TenantConfig = Depends(_require_admin),
    ) -> PlainTextResponse:
        ndjson = audit_ledger.export_jsonl(tenant_id=tenant_id, limit=limit)
        return PlainTextResponse(
            content=ndjson,
            media_type="application/x-ndjson",
        )

    @fastapi_app.get("/metrics")
    async def prometheus_metrics(
        _: TenantConfig = Depends(_require_admin),
    ) -> PlainTextResponse:
        return PlainTextResponse(
            content=metrics.render_prometheus(),
            media_type="text/plain; version=0.0.4",
        )

    return fastapi_app


def _init_module_app() -> Optional[FastAPI]:
    """Initialize module-level ASGI app with explicit diagnostic logging."""
    try:
        return create_app()
    except Exception:
        logger.exception(
            "Failed to initialize module-level FastAPI app in lta.app; check environment config"
        )
        raise


app: Optional[FastAPI] = _init_module_app()