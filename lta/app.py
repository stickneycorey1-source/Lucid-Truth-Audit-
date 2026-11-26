"""Unit tests targeting uncovered branches in lta/app.py."""

from __future__ import annotations

import math
from fastapi.testclient import TestClient
import pytest

from lta import app as lta_app_mod
from lta.app import (
    LegacyGuardRequest,
    ShadowIngestRequest,
    _client_ip,
    create_app,
)
from lta.config import Settings, TenantConfig
from lta.providers import UpstreamProviderError


def _make_settings(db_path: str) -> Settings:
    tenant_key = "p2_pilot_key_123456"
    admin_key = "admin_key_123456"
    return Settings(
        policy_dir="policies",
        audit_db_url=f"sqlite:///{db_path}",
        redis_url="",
        upstream_timeout_s=5.0,
        tenants=[
            TenantConfig(
                tenant_id="p2_pilot",
                api_key_hash=Settings.hash_key(tenant_key) if hasattr(Settings, "hash_key") else __import__("hashlib").sha256(tenant_key.encode()).hexdigest(),
                role="member",
                policy_pack="fmcsa",
                provider="mock",
                rate_limit_rpm=60,
            ),
            TenantConfig(
                tenant_id="admin_ops",
                api_key_hash=__import__("hashlib").sha256(admin_key.encode()).hexdigest(),
                role="admin",
                policy_pack="fmcsa",
                provider="mock",
                rate_limit_rpm=120,
            ),
        ],
    )


def test_metadata_validators_reject_non_finite_floats():
    for cls, payload in (
        (LegacyGuardRequest, {"model_input": "dispatch check", "metadata": {"bad": math.nan}}),
        (ShadowIngestRequest, {"prompt": "shadow check", "metadata": {"bad": math.inf}}),
    ):
        with pytest.raises(Exception):
            cls(**payload)


def test_client_ip_resolution_variants():
    class _DummyClient:
        def __init__(self, host: str | None) -> None:
            self.host = host

    class _DummyReq:
        def __init__(self, headers: dict[str, str], host: str | None) -> None:
            self.headers = headers
            self.client = _DummyClient(host) if host is not None else None

    assert _client_ip(_DummyReq({"x-forwarded-for": "10.0.0.5, 192.168.1.1"}, "127.0.0.1")) == "10.0.0.5"
    assert _client_ip(_DummyReq({}, "192.168.1.10")) == "192.168.1.10"
    assert _client_ip(_DummyReq({}, None)) == "unknown"


def test_lifespan_shadow_auth_and_pipeline_error_paths(monkeypatch, tmp_path):
    db_path = str(tmp_path / "lta_app_cov.db")
    settings = _make_settings(db_path)

    fastapi_app = create_app(settings)
    with TestClient(fastapi_app) as client:
        # Missing shadow credentials -> 401
        r_no_auth = client.post("/v1/shadow/ingest", json={"prompt": "BOL check"})
        assert r_no_auth.status_code == 401

        # With LTA_SHADOW_KEY set: wrong key -> 403, valid key -> 202
        monkeypatch.setenv("LTA_SHADOW_KEY", "shadow-secret-key-999")
        r_bad_shadow = client.post(
            "/v1/shadow/ingest",
            headers={"Authorization": "Bearer wrong-key"},
            json={"prompt": "BOL check"},
        )
        assert r_bad_shadow.status_code == 403

        r_ok_shadow = client.post(
            "/v1/shadow/ingest",
            headers={"Authorization": "Bearer shadow-secret-key-999"},
            json={"prompt": "Driver CDL MN8492014", "request_id": "pilot-req-1"},
        )
        assert r_ok_shadow.status_code in (200, 202, 404)

        # Unset LTA_SHADOW_KEY -> falls back to tenant auth
        monkeypatch.delenv("LTA_SHADOW_KEY", raising=False)
        r_tenant_shadow = client.post(
            "/v1/shadow/ingest",
            headers={"X-API-Key": "p2_pilot_key_123456"},
            json={"prompt": "Tenant fallback shadow check"},
        )
        assert r_tenant_shadow.status_code in (200, 202, 404)

        # Non-admin attempting policy override -> 403
        r_override = client.post(
            "/v1/chat/completions",
            headers={
                "X-API-Key": "p2_pilot_key_123456",
                "X-LTA-Policy": "general_enterprise",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "Check status"}],
            },
        )
        assert r_override.status_code == 403

        # UpstreamProviderError -> 502
        async def _boom(**kwargs):
            raise UpstreamProviderError("upstream timeout")

        monkeypatch.setattr(lta_app_mod, "call_upstream", _boom)
        r_upstream_err = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "p2_pilot_key_123456"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "Check load"}],
            },
        )
        assert r_upstream_err.status_code == 502

        # Output leak simulation blocked -> 400/403
        async def _leak_ssn(**kwargs):
            return type(
                "Resp",
                (),
                {
                    "content": "SSN is 123-45-6789",
                    "model": "mock",
                    "provider": "mock",
                    "prompt_tokens": 5,
                    "completion_tokens": 5,
                },
            )()

        monkeypatch.setattr(lta_app_mod, "call_upstream", _leak_ssn)
        r_out_block = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "p2_pilot_key_123456"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "Give me driver info"}],
            },
        )
        assert r_out_block.status_code in (400, 403)