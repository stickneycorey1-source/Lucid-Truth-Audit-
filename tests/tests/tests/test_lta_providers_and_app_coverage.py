"""High-impact tests for lta/providers.py and lta/app.py coverage."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import lta.providers as providers_mod
from lta.app import create_app
from lta.config import Settings
from lta.providers import UpstreamProviderError, _post_json, call_upstream, validate_upstream_url


def test_validate_upstream_url_enforces_https_and_allows_local() -> None:
    assert validate_upstream_url("https://api.openai.com/v1/") == "https://api.openai.com/v1"
    assert validate_upstream_url("http://localhost:11434/v1") == "http://localhost:11434/v1"
    with pytest.raises(UpstreamProviderError):
        validate_upstream_url("http://api.openai.com/v1")


def test_simulated_fallback_and_secret_leak_triggers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LTA_OPENAI_API_KEY", raising=False)

    with pytest.raises(UpstreamProviderError):
        asyncio.run(
            call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "Hello"}],
            )
        )

    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "true")
    res_sys = asyncio.run(
        call_upstream(
            provider="openai",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "__simulate_leak_system__"}],
        )
    )
    assert "Internal System Instructions" in res_sys.content

    res_ssn = asyncio.run(
        call_upstream(
            provider="openai",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "__simulate_leak_ssn__"}],
        )
    )
    assert "123-45-6789" in res_ssn.content

    res_secret = asyncio.run(
        call_upstream(
            provider="openai",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "__simulate_leak_secret__"}],
        )
    )
    assert "[REDACTED_SECRET]" in providers_mod._scrub_secrets(res_secret.content)


def test_post_json_retries_transient_503_and_scrubs_http_error_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LTA_ALLOW_SIMULATED_FALLBACK", raising=False)
    attempts = {"count": 0}

    async def _flaky_handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return httpx.Response(503, json={"error": {"message": "temporary overload"}})
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "Recovered cleanly"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            },
        )

    async def _run_retry() -> None:
        transport = httpx.MockTransport(_flaky_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            data = await _post_json(
                "https://api.openai.com/v1/chat/completions",
                payload={"model": "gpt-4o-mini", "messages": []},
                timeout_s=5.0,
                http_client=client,
                max_retries=1,
            )
            assert data["choices"][0]["message"]["content"] == "Recovered cleanly"

    asyncio.run(_run_retry())
    assert attempts["count"] == 2

    async def _auth_fail_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"message": "Invalid key sk-1234567890abcdef1234567890"}},
        )

    monkeypatch.setenv("OPENAI_API_KEY", "sk-1234567890abcdef1234567890")

    async def _run_scrub() -> None:
        transport = httpx.MockTransport(_auth_fail_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(UpstreamProviderError) as exc_info:
                await call_upstream(
                    provider="openai",
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": "Hi"}],
                    http_client=client,
                )
            assert "sk-1234567890abcdef1234567890" not in str(exc_info.value)
            assert "[REDACTED_SECRET]" in str(exc_info.value)

    asyncio.run(_run_scrub())


def test_gemini_and_anthropic_formatting_and_empty_candidate_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyTestKey12345678901234567890")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345678901234567890")

    async def _gem_ok(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert "systemInstruction" in body
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": "internal thought", "thought": True},
                                {"text": "Final Gemini answer."},
                            ]
                        }
                    }
                ],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 4},
            },
        )

    async def _run_gem() -> None:
        transport = httpx.MockTransport(_gem_ok)
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await call_upstream(
                provider="gemini",
                model="gemini-2.5-flash",
                messages=[
                    {"role": "system", "content": "Be concise."},
                    {"role": "user", "content": "Status?"},
                ],
                http_client=client,
            )
            assert resp.content == "Final Gemini answer."

    asyncio.run(_run_gem())

    async def _gem_empty(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"candidates": [{"finishReason": "SAFETY"}]})

    async def _run_gem_empty() -> None:
        transport = httpx.MockTransport(_gem_empty)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(UpstreamProviderError, match="finishReason=SAFETY"):
                await call_upstream(
                    provider="gemini",
                    model="gemini-2.5-flash",
                    messages=[{"role": "user", "content": "Test"}],
                    http_client=client,
                )

    asyncio.run(_run_gem_empty())


def test_lta_app_gateway_endpoints_and_audit_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "lta_gateway_test.db"
    client_key = "test-client-key-abc"
    admin_key = "test-admin-key-xyz"

    monkeypatch.setenv("LTA_DEFAULT_PROVIDER", "mock")
    monkeypatch.setenv("LTA_AUDIT_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv(
        "LTA_TENANTS_JSON",
        json.dumps(
            [
                {
                    "tenant_id": "tenant_client",
                    "api_key": client_key,
                    "policy_pack": "general_enterprise",
                    "provider": "mock",
                    "rate_limit_rpm": 120,
                    "role": "client",
                },
                {
                    "tenant_id": "tenant_admin",
                    "api_key": admin_key,
                    "policy_pack": "general_enterprise",
                    "provider": "mock",
                    "rate_limit_rpm": 120,
                    "role": "admin",
                },
            ]
        ),
    )

    app = create_app(Settings.from_env())
    with TestClient(app) as client:
        r_health = client.get("/healthz")
        assert r_health.status_code == 200

        r_ready = client.get("/readyz")
        assert r_ready.status_code == 200

        r_chat = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": client_key},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]},
        )
        assert r_chat.status_code == 200

        r_verify = client.get("/v1/audit/verify", headers={"X-API-Key": admin_key})
        assert r_verify.status_code == 200
        assert r_verify.json().get("chain_valid") is True