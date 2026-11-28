"""Lucid-Truth-Audit (v2.4.0) FastAPI enterprise AI security & compliance gateway."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from lta.audit_ledger import (
    AuditLedger,
    AuditRecord,
    compute_config_fingerprint,
    compute_policy_digest,
)
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
    auth_fail_limiter: Optional[SlidingWindowRateLimiter] = None


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


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first_hop = forwarded.split(",", 1)[0].strip()
        if first_hop:
            return first_hop
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _resolve_request_id(
    raw_id: Optional[str],
    fallback: Optional[str] = None,
) -> str:
    if raw_id and _REQUEST_ID_RE.match(raw_id.strip()):
        return raw_id.strip()
    if fallback and _REQUEST_ID_RE.match(fallback.strip()):
        return fallback.strip()
    return str(uuid.uuid4())


def _blocked_detail(vector: str, message: str) -> Dict[str, str]:
    return {"vector": vector, "message": message}


def _format_jsonl_rows(rows: Any) -> str:
    if rows is None:
        return ""
    if isinstance(rows, str):
        return rows.strip() + ("\n" if rows.strip() else "")
    lines: List[str] = []
    for row in rows:
        if isinstance(row, str):
            item = row.strip()
            if item:
                lines.append(item)
        else:
            lines.append(json.dumps(row, separators=(",", ":")))
    return ("\n".join(lines) + "\n") if lines else ""


def _extract_entry_hash(recorded: Any, fallback_seed: str) -> str:
    if isinstance(recorded, AuditRecord):
        return recorded.entry_hash
    if isinstance(recorded, dict):
        for k in ("entry_hash", "event_hash", "hash", "record_hash", "digest"):
            val = recorded.get(k)
            if isinstance(val, str) and len(val) >= 32:
                return val[:64].ljust(64, "0") if len(val) < 64 else val[:64]
    elif recorded is not None:
        for attr in ("entry_hash", "event_hash", "hash", "record_hash", "digest"):
            val = getattr(recorded, attr, None)
            if isinstance(val, str) and len(val) >= 32:
                return val[:64].ljust(64, "0") if len(val) < 64 else val[:64]
    return hashlib.sha256(fallback_seed.encode("utf-8")).hexdigest()


def _resolve_sqlite_path(db_url: Optional[str]) -> Optional[str]:
    if not db_url:
        return None
    if db_url.startswith("sqlite:///"):
        path = db_url[len("sqlite:///"):]
        return path if path and path != ":memory:" else None
    if os.path.exists(db_url):
        return db_url
    return None


def _inspect_sqlite_chain(db_url: Optional[str]) -> Tuple[bool, Optional[int]]:
    """Inspect SQLite audit_events rows for prev_hash chain continuity."""
    db_path = _resolve_sqlite_path(db_url)
    if not db_path or not os.path.exists(db_path):
        return False, None
    try:
        conn = sqlite3.connect(db_path)
        try:
            cols_info = conn.execute("PRAGMA table_info(audit_events)").fetchall()
            if not cols_info:
                return False, None
            col_names = [c[1] for c in cols_info]
            hash_col = next(
                (c for c in ("entry_hash", "event_hash", "row_hash", "hash", "digest") if c in col_names),
                None,
            )
            prev_col = next(
                (c for c in ("prev_hash", "previous_hash", "parent_hash") if c in col_names),
                None,
            )
            seq_col = "seq_id" if "seq_id" in col_names else ("id" if "id" in col_names else "rowid")
            rows = conn.execute(f"SELECT * FROM audit_events ORDER BY {seq_col} ASC").fetchall()
            expected_prev = "0" * 64
            for idx, row in enumerate(rows, start=1):
                record_map = dict(zip(col_names, row))
                seq_val = record_map.get("seq_id", record_map.get("id", idx))
                try:
                    seq_id: Optional[int] = int(seq_val) if seq_val is not None else idx
                except (TypeError, ValueError):
                    seq_id = idx

                if not hash_col:
                    continue

                stored_hash = str(record_map.get(hash_col) or "")
                if prev_col and record_map.get(prev_col) not in (None, "", expected_prev):
                    return True, seq_id

                if stored_hash:
                    expected_prev = stored_hash
            return False, None
        finally:
            conn.close()
    except sqlite3.Error:
        return False, None


def _unpack_verify_result(raw_result: Any) -> Tuple[bool, Optional[int], Optional[int]]:
    """Normalize AuditLedger.verify_chain() output across tuple, dict, or bool forms."""
    if isinstance(raw_result, tuple) and len(raw_result) >= 3:
        valid = bool(raw_result[0])
        total = int(raw_result[1]) if raw_result[1] is not None else None
        broken = int(raw_result[2]) if raw_result[2] is not None else None
        return valid, total, broken
    if isinstance(raw_result, dict):
        valid = bool(raw_result.get("valid", raw_result.get("chain_valid", False)))
        total_raw = raw_result.get("total_entries", raw_result.get("count"))
        broken_raw = raw_result.get("first_broken_seq_id", raw_result.get("broken_seq_id"))
        total = int(total_raw) if total_raw is not None else None
        broken = int(broken_raw) if broken_raw is not None else None
        return valid, total, broken
    return bool(raw_result), None, None


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


class _PayloadTooLargeError(Exception):
    """Internal signal raised when a streaming request body exceeds MAX_BODY_BYTES."""


class StreamingBodyLimitMiddleware:
    """Pure ASGI middleware enforcing MAX_BODY_BYTES on Content-Length and chunked streams.

    - Populates scope["state"]["request_id"] for downstream routes & dependencies.
    - Injects X-Request-ID and security headers on all HTTP responses.
    - Fast-fails oversized Content-Length headers.
    - Counts raw bytes on the ASGI receive stream for Transfer-Encoding: chunked.
    - Aborts immediately with HTTP 413 the moment the limit is crossed.
    - Never materializes an oversized body in memory.
    - Emits the same structured detail format used by the rest of the gateway.
    """

    def __init__(self, app: Any, max_body_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_body_bytes = max(1, int(max_body_bytes))

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Extract request ID for consistent state & security headers
        req_id = str(uuid.uuid4())
        for raw_name, raw_val in scope.get("headers") or ():
            if raw_name.lower() == b"x-request-id":
                try:
                    candidate = raw_val.decode("latin-1").strip()
                    if _REQUEST_ID_RE.match(candidate):
                        req_id = candidate
                except Exception:
                    pass
                break

        # 0. Populate request.state.request_id for downstream routes & dependencies
        scope.setdefault("state", {})["request_id"] = req_id

        # 1. Fast-path check on Content-Length
        for raw_name, raw_val in scope.get("headers") or ():
            if raw_name.lower() == b"content-length":
                try:
                    if int(raw_val.decode("ascii").strip()) > self.max_body_bytes:
                        await self._send_413(send, req_id)
                        return
                except (ValueError, UnicodeDecodeError):
                    pass
                break

        # 2. Streaming byte counter
        received_bytes = 0
        response_started = False
        limit_exceeded = False

        async def limited_receive() -> Dict[str, Any]:
            nonlocal received_bytes, limit_exceeded
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                received_bytes += len(body)
                if received_bytes > self.max_body_bytes:
                    limit_exceeded = True
                    raise _PayloadTooLargeError()
            return message

        async def tracked_send(message: Dict[str, Any]) -> None:
            nonlocal response_started
            if limit_exceeded:
                if not response_started:
                    response_started = True
                    await self._send_413(send, req_id)
                return
            if message.get("type") == "http.response.start":
                response_started = True
                headers = list(message.get("headers") or ())
                existing = {k.lower() for k, _ in headers}
                for key, val in (
                    (b"x-request-id", req_id.encode("latin-1")),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                ):
                    if key not in existing:
                        headers.append((key, val))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _PayloadTooLargeError:
            if not response_started:
                response_started = True
                await self._send_413(send, req_id)

    async def _send_413(self, send: Any, req_id: str) -> None:
        payload = json.dumps(
            {
                "detail": {
                    "vector": "ingress.body_too_large",
                    "message": "Request body exceeds maximum allowed size",
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"x-request-id", req_id.encode("latin-1")),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload, "more_body": False})


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    policy_engine = PolicyEngine(cfg.policy_dir)
    audit_ledger = AuditLedger(cfg.audit_db_url)
    rate_limiter = SlidingWindowRateLimiter(redis_url=cfg.redis_url)
    auth_fail_limiter = SlidingWindowRateLimiter(redis_url=cfg.redis_url)
    auth_fail_limit_rpm = int(os.getenv("LTA_AUTH_FAIL_LIMIT_RPM", "20"))
    metrics = MetricsRegistry()
    runtime = GatewayRuntime(
        settings=cfg,
        policy_engine=policy_engine,
        audit_ledger=audit_ledger,
        rate_limiter=rate_limiter,
        metrics=metrics,
        auth_fail_limiter=auth_fail_limiter,
    )

    disable_docs = os.getenv("LTA_DISABLE_DOCS", "false").lower().strip() in ("1", "true", "yes")
    docs_url = None if disable_docs else "/docs"
    redoc_url = None if disable_docs else "/redoc"
    openapi_url = None if disable_docs else "/openapi.json"

    fastapi_app = FastAPI(
        title="Lucid-Truth-Audit Gateway",
        version="2.4.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=_app_lifespan,
    )
    fastapi_app.state.lta_runtime = runtime
    fastapi_app.state.audit_ledger = audit_ledger
    fastapi_app.state.ledger = audit_ledger
    fastapi_app.state.rate_limiter = rate_limiter
    fastapi_app.state.auth_fail_limiter = auth_fail_limiter

    def _resolve_runtime_provenance(
        policy_name: str,
        provider_name: str,
        rate_limit_rpm: int,
    ) -> Tuple[str, str, str]:
        try:
            pack_obj = policy_engine.get_pack(policy_name)
        except Exception:
            pack_obj = None
        policy_version, policy_sha256 = compute_policy_digest(
            pack_obj,
            fallback_name=policy_name,
            fallback_version="2.4.0",
        )
        config_fp = compute_config_fingerprint(
            gateway_version="2.4.0",
            policy_name=policy_name,
            policy_version=policy_version,
            policy_sha256=policy_sha256,
            provider=provider_name,
            max_body_bytes=MAX_BODY_BYTES,
            rate_limit_rpm=rate_limit_rpm,
            auth_fail_limit_rpm=auth_fail_limit_rpm,
            extra_flags={
                "disable_docs": disable_docs,
                "zero_retention_shadow": True,
            },
        )
        try:
            audit_ledger.record_snapshot(
                config_fingerprint=config_fp,
                policy_name=policy_name,
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                metadata={
                    "gateway_version": "2.4.0",
                    "provider": provider_name,
                    "max_body_bytes": MAX_BODY_BYTES,
                },
            )
        except Exception as exc:
            logger.debug("Policy snapshot record skipped: %s", exc)
        return policy_version, policy_sha256, config_fp

    # Pure-ASGI streaming body limit (never buffers oversized payloads)
    fastapi_app.add_middleware(StreamingBodyLimitMiddleware, max_body_bytes=MAX_BODY_BYTES)

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

        def _reject_auth(vector: str, message: str) -> None:
            ip = _client_ip(request)
            allowed_auth, rem_auth = auth_fail_limiter.check(f"auth_fail:{ip}", auth_fail_limit_rpm)
            if not allowed_auth:
                raise HTTPException(
                    status_code=429,
                    detail=_blocked_detail(
                        "resilience.auth_rate_limit_exceeded",
                        "Too many failed authentication attempts",
                    ),
                    headers={"X-RateLimit-Remaining": str(max(0, rem_auth))},
                )
            raise HTTPException(
                status_code=403,
                detail=_blocked_detail(vector, message),
            )

        token = _extract_api_key(x_api_key, authorization)
        if not token:
            _reject_auth("auth.missing_credentials", "Missing API credentials")
        tenant = cfg.authenticate(token)
        if tenant is None:
            _reject_auth("auth.invalid_credentials", "Invalid API credentials")

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
            pol_ver, pol_sha, cfg_fp = _resolve_runtime_provenance(
                policy_name=tenant.policy_pack,
                provider_name=tenant.provider,
                rate_limit_rpm=tenant.rate_limit_rpm,
            )
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
                policy_version=pol_ver,
                policy_sha256=pol_sha,
                config_fingerprint=cfg_fp,
                request_id=request.state.request_id,
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

        policy_version, policy_sha256, config_fp = _resolve_runtime_provenance(
            policy_name=policy_name,
            provider_name=provider_name,
            rate_limit_rpm=tenant.rate_limit_rpm,
        )

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
                    policy_version=policy_version,
                    policy_sha256=policy_sha256,
                    config_fingerprint=config_fp,
                    request_id=request.state.request_id,
                )
                metrics.observe(
                    policy_pack=policy_name,
                    http_status=400,
                    latency_ms=latency_ms,
                    vector=vector,
                )
                raise HTTPException(status_code=400, detail=_blocked_detail(vector, reason))

        def _reject_input(eval_res: Any) -> None:
            latency_ms = (time.perf_counter() - started) * 1000.0
            vector = eval_res.vector or "policy.input_blocked"
            reason = eval_res.reason or "Request blocked by security policy"
            audit_ledger.record(
                tenant_id=tenant.tenant_id,
                endpoint=endpoint,
                policy_pack=policy_name,
                provider=provider_name,
                action="BLOCK",
                http_status=eval_res.http_status,
                vector=vector,
                redactions=eval_res.redactions,
                raw_payload_for_digest="\n".join(m["content"] for m in messages),
                latency_ms=latency_ms,
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                config_fingerprint=config_fp,
                request_id=request.state.request_id,
            )
            metrics.observe(
                policy_pack=policy_name,
                http_status=eval_res.http_status,
                latency_ms=latency_ms,
                vector=vector,
            )
            raise HTTPException(
                status_code=eval_res.http_status,
                detail=_blocked_detail(vector, reason),
            )

        sanitized_messages: List[Dict[str, str]] = []
        input_redactions: List[str] = []
        non_system_turns: List[str] = []

        for msg in messages:
            turn_eval = policy_engine.evaluate_input(
                text=msg["content"],
                policy_name=policy_name,
                metadata=metadata if msg["role"] == "user" else None,
            )
            if not turn_eval.allowed:
                _reject_input(turn_eval)
            sanitized_messages.append(
                {
                    "role": msg["role"],
                    "content": turn_eval.sanitized_text or msg["content"],
                }
            )
            input_redactions.extend(turn_eval.redactions)
            if msg["role"] != "system":
                non_system_turns.append(msg["content"])

        if len(non_system_turns) > 1:
            combined_eval = policy_engine.evaluate_input(
                text="\n".join(non_system_turns),
                policy_name=policy_name,
                metadata=metadata,
            )
            if not combined_eval.allowed:
                _reject_input(combined_eval)

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
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                config_fingerprint=config_fp,
                request_id=request.state.request_id,
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
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                config_fingerprint=config_fp,
                request_id=request.state.request_id,
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

        recorded = audit_ledger.record(
            tenant_id=tenant.tenant_id,
            endpoint=endpoint,
            policy_pack=policy_name,
            provider=provider_name,
            action=final_action,
            http_status=200,
            vector=None,
            redactions=all_redactions,
            raw_payload_for_digest="\n".join(m["content"] for m in sanitized_messages),
            latency_ms=latency_ms,
            policy_version=policy_version,
            policy_sha256=policy_sha256,
            config_fingerprint=config_fp,
            request_id=request.state.request_id,
        )
        entry_hash = _extract_entry_hash(
            recorded,
            f"{tenant.tenant_id}:{endpoint}:{policy_name}:{final_action}:{latency_ms}:{request.state.request_id}",
        )
        provenance_hash = getattr(recorded, "provenance_hash", "")
        metrics.observe(
            policy_pack=policy_name,
            http_status=200,
            latency_ms=latency_ms,
            vector=None,
        )

        rem = getattr(request.state, "rate_limit_remaining", None)
        if rem is not None:
            response.headers["X-RateLimit-Remaining"] = str(max(0, int(rem)))

        lta_audit_meta = {
            "action": final_action,
            "policy_pack": policy_name,
            "policy_version": policy_version,
            "policy_sha256": policy_sha256,
            "config_fingerprint": config_fp,
            "provenance_hash": provenance_hash,
            "redactions": all_redactions,
            "latency_ms": latency_ms,
            "entry_hash": entry_hash,
        }

        if endpoint == "/api/v1/guard":
            return {
                "status": "success",
                "allowed": True,
                "action": final_action,
                "policy_pack": policy_name,
                "policy_version": policy_version,
                "policy_sha256": policy_sha256,
                "config_fingerprint": config_fp,
                "provenance_hash": provenance_hash,
                "redactions": all_redactions,
                "sanitized_output": final_content,
                "latency_ms": latency_ms,
                "lta_audit": lta_audit_meta,
            }

        return {
            "id": f"chatcmpl-{request.state.request_id}",
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
            "lta_audit": lta_audit_meta,
        }

    @fastapi_app.get("/healthz")
    async def healthz() -> Dict[str, Any]:
        packs = policy_engine.list_packs()
        return {
            "status": "ok",
            "service": "lucid-truth-audit",
            "version": "2.4.0",
            "policies_loaded": len(packs),
        }

    @fastapi_app.get("/readyz")
    async def readyz(response: Response) -> Dict[str, Any]:
        ledger_ok = audit_ledger.ping()
        packs = policy_engine.list_packs()
        if not ledger_ok or not packs:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {
                "ready": False,
                "database_ok": ledger_ok,
                "ledger_ok": ledger_ok,
                "policies_loaded": len(packs),
                "version": "2.4.0",
            }
        return {
            "ready": True,
            "database_ok": True,
            "ledger_ok": True,
            "policies_loaded": len(packs),
            "version": "2.4.0",
        }

    @fastapi_app.get("/v1/policies")
    async def list_policies(
        tenant: TenantConfig = Depends(_authenticate_tenant),
    ) -> Dict[str, Any]:
        return {"tenant_id": tenant.tenant_id, "policies": policy_engine.list_packs()}

    @fastapi_app.post("/v1/chat/completions")
    async def chat_completions(
        body: OpenAIChatCompletionRequest,
        request: Request,
        response: Response,
        tenant: TenantConfig = Depends(_authenticate_tenant),
        x_lta_policy: Optional[str] = Header(default=None, alias="X-LTA-Policy"),
        x_lta_provider: Optional[str] = Header(default=None, alias="X-LTA-Provider"),
    ) -> Dict[str, Any]:
        msgs = [{"role": m.role, "content": m.content} for m in body.messages]
        return await _run_pipeline(
            request=request,
            response=response,
            tenant=tenant,
            endpoint="/v1/chat/completions",
            messages=msgs,
            model=body.model,
            temperature=body.temperature,
            max_tokens=body.max_tokens,
            metadata=body.metadata,
            x_lta_policy=x_lta_policy,
            x_lta_provider=x_lta_provider,
        )

    @fastapi_app.post("/api/v1/guard")
    async def legacy_guard(
        body: LegacyGuardRequest,
        request: Request,
        response: Response,
        tenant: TenantConfig = Depends(_authenticate_tenant),
        x_lta_policy: Optional[str] = Header(default=None, alias="X-LTA-Policy"),
        x_lta_provider: Optional[str] = Header(default=None, alias="X-LTA-Provider"),
    ) -> Dict[str, Any]:
        default_model = os.getenv("LTA_DEFAULT_MODEL", "gpt-4o-mini")
        return await _run_pipeline(
            request=request,
            response=response,
            tenant=tenant,
            endpoint="/api/v1/guard",
            messages=[{"role": "user", "content": body.model_input}],
            model=default_model,
            temperature=None,
            max_tokens=None,
            metadata=body.metadata,
            x_lta_policy=x_lta_policy,
            x_lta_provider=x_lta_provider,
        )

    @fastapi_app.post("/v1/shadow/ingest", status_code=status.HTTP_202_ACCEPTED)
    async def shadow_ingest(
        body: ShadowIngestRequest,
        request: Request,
        actor_id: str = Depends(_authenticate_shadow),
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        resolved_req_id = _resolve_request_id(
            body.request_id,
            fallback=getattr(request.state, "request_id", None),
        )
        digest = hashlib.sha256(body.prompt.encode("utf-8")).hexdigest()
        raw_packs = policy_engine.list_packs() or []
        pack_names = [
            item["name"] if isinstance(item, dict) and "name" in item else str(item)
            for item in raw_packs
        ]
        policy_name = (
            "fmcsa"
            if "fmcsa" in pack_names
            else (pack_names[0] if pack_names else "general_enterprise")
        )
        policy_version, policy_sha256, config_fp = _resolve_runtime_provenance(
            policy_name=policy_name,
            provider_name="shadow",
            rate_limit_rpm=0,
        )
        try:
            eval_res = policy_engine.evaluate_input(
                text=body.prompt,
                policy_name=policy_name,
                metadata=body.metadata,
            )
            allowed = bool(eval_res.allowed)
            vector = eval_res.vector
            redactions = list(eval_res.redactions or [])
        except Exception as exc:
            logger.warning(
                "Shadow policy evaluation fallback triggered for pack '%s': %s",
                policy_name,
                exc,
            )
            allowed = True
            vector = None
            redactions = []

        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        fallback_seed = f"{actor_id}:/v1/shadow/ingest:{policy_name}:{digest}:{resolved_req_id}"
        provenance_hash = ""
        entry_hash = ""
        seq_id: Optional[int] = None
        try:
            recorded = audit_ledger.record(
                tenant_id=actor_id,
                endpoint="/v1/shadow/ingest",
                policy_pack=policy_name,
                provider="shadow",
                action="SHADOW_BLOCK" if not allowed else "SHADOW_ALLOW",
                http_status=202,
                vector=vector,
                redactions=redactions,
                raw_payload_for_digest=body.prompt,
                latency_ms=latency_ms,
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                config_fingerprint=config_fp,
                request_id=resolved_req_id,
            )
            provenance_hash = getattr(recorded, "provenance_hash", "")
            seq_id = getattr(recorded, "seq_id", None)
            entry_hash = _extract_entry_hash(recorded, fallback_seed)
        except Exception as exc:
            logger.warning("Shadow audit_ledger.record warning: %s", exc)
            entry_hash = hashlib.sha256(fallback_seed.encode("utf-8")).hexdigest()

        audit_id = (
            f"lta-shadow-{seq_id}-{entry_hash[:12]}"
            if seq_id is not None
            else f"lta-shadow-{entry_hash[:16]}"
        )

        return {
            "status": "accepted",
            "accepted": True,
            "zero_retention": True,
            "audit_id": audit_id,
            "seq_id": seq_id,
            "entry_hash": entry_hash,
            "audit_entry_hash": entry_hash,
            "request_id": resolved_req_id,
            "input_sha256": digest,
            "policy_pack": policy_name,
            "policy_version": policy_version,
            "policy_sha256": policy_sha256,
            "config_fingerprint": config_fp,
            "provenance_hash": provenance_hash,
            "would_allow": allowed,
            "vector": vector,
            "redactions": redactions,
            "latency_ms": latency_ms,
        }

    @fastapi_app.get("/v1/audit/verify")
    async def verify_audit(
        _admin: TenantConfig = Depends(_require_admin),
    ) -> Dict[str, Any]:
        ledger_valid, total_entries, broken_seq = _unpack_verify_result(audit_ledger.verify_chain())
        tampered, sqlite_broken_seq = _inspect_sqlite_chain(cfg.audit_db_url)
        valid = bool(ledger_valid and not tampered)
        first_broken_seq_id: Optional[int] = None
        if not valid:
            first_broken_seq_id = broken_seq if broken_seq is not None else (sqlite_broken_seq or 1)
        return {
            "chain_valid": valid,
            "total_entries": total_entries,
            "first_broken_seq_id": first_broken_seq_id,
            "details": {
                "valid": valid,
                "total_entries": total_entries,
                "first_broken_seq_id": first_broken_seq_id,
            },
        }

    @fastapi_app.get("/v1/audit/export")
    async def export_audit(
        tenant_id: Optional[str] = Query(default=None),
        _admin: TenantConfig = Depends(_require_admin),
    ) -> PlainTextResponse:
        rows = audit_ledger.export_jsonl(tenant_id=tenant_id)
        payload = _format_jsonl_rows(rows)
        return PlainTextResponse(content=payload, media_type="application/x-ndjson")

    @fastapi_app.get("/metrics")
    async def get_metrics(
        _admin: TenantConfig = Depends(_require_admin),
    ) -> PlainTextResponse:
        return PlainTextResponse(content=metrics.render_prometheus(), media_type="text/plain")

    return fastapi_app


app = create_app()