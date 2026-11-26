"""Unit tests for lta/providers.py (v2.4.1) covering all upstream adapters and error paths."""

from __future__ import annotations

import json
import pytest
import httpx

from lta import providers
from lta.providers import (
    ProviderResponse,
    UpstreamProviderError,
    _fallback_enabled,
    _post_json,
    _scrub_secrets,
    _simulate_mock_response,
    call_upstream,
    validate_upstream_url,
)


# ---------- Helpers & Validation ----------

def test_scrub_secrets_redacts_known_token_patterns():
    raw = (
        "openai=sk-1234567890abcdef12 gh=ghp_1234567890abcdefghij12 "
        "aws=AKIA1234567890ABCDEF gem=AIzaSy1234567890abcdefghij "
        "hdr=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    )
    scrubbed = _scrub_secrets(raw)
    assert "sk-1234567890abcdef12" not in scrubbed
    assert "ghp_1234567890abcdefghij12" not in scrubbed
    assert "AKIA1234567890ABCDEF" not in scrubbed
    assert "AIzaSy1234567890abcdefghij" not in scrubbed
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in scrubbed
    assert scrubbed.count("[REDACTED_SECRET]") == 5


def test_validate_upstream_url_accepts_https_and_local_http():
    assert validate_upstream_url("https://api.openai.com/v1/") == "https://api.openai.com/v1"
    assert validate_upstream_url("http://localhost:11434/v1/") == "http://localhost:11434/v1"
    assert validate_upstream_url("http://127.0.0.1:8080/v1") == "http://127.0.0.1:8080/v1"
    assert validate_upstream_url("http://ollama:11434/v1") == "http://ollama:11434/v1"


@pytest.mark.parametrize("bad_url", [
    "http://api.openai.com/v1",
    "ftp://example.com/v1",
    "https://",
])
def test_validate_upstream_url_rejects_insecure_remote_urls(bad_url):
    with pytest.raises(UpstreamProviderError):
        validate_upstream_url(bad_url)


@pytest.mark.parametrize("env_val,expected", [
    ("true", True),
    ("1", True),
    ("YES", True),
    ("false", False),
    ("0", False),
    ("", False),
])
def test_fallback_enabled_env_parsing(monkeypatch, env_val, expected):
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", env_val)
    assert _fallback_enabled() is expected


@pytest.mark.parametrize("marker,expected_substr", [
    ("__simulate_leak_system__", "Internal System Instructions"),
    ("__simulate_leak_ssn__", "123-45-6789"),
    ("__simulate_leak_secret__", "sk-prod1234567890abcdef1234"),
    ("normal dispatch note", "[LTA Verified Upstream Response]"),
])
def test_simulate_mock_response_variants(marker, expected_substr):
    res = _simulate_mock_response(
        model="gpt-4o-mini",
        provider_label="mock",
        messages=[{"role": "system", "content": "sys"}, {"role": "user", "content": marker}],
    )
    assert isinstance(res, ProviderResponse)
    assert expected_substr in res.content


# ---------- _post_json ----------

@pytest.mark.asyncio
async def test_post_json_with_injected_client():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-test"] == "1"
        body = json.loads(request.content.decode())
        return httpx.Response(200, json={"echo": body["hello"]})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        data = await _post_json(
            "https://example.test/v1/test",
            headers={"x-test": "1"},
            payload={"hello": "world"},
            timeout_s=5.0,
            http_client=client,
        )
    assert data == {"echo": "world"}


@pytest.mark.asyncio
async def test_post_json_without_injected_client(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    real_async_client = httpx.AsyncClient

    class PatchedAsyncClient(real_async_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(providers.httpx, "AsyncClient", PatchedAsyncClient)
    data = await _post_json(
        "https://example.test/v1/test",
        payload={"ping": "pong"},
        timeout_s=5.0,
        http_client=None,
    )
    assert data == {"ok": True}


# ---------- call_upstream: mock & missing keys / fallback ----------

@pytest.mark.asyncio
async def test_call_upstream_mock_provider():
    res = await call_upstream(
        provider="mock",
        model="lta-mock",
        messages=[{"role": "user", "content": "Check load #104"}],
    )
    assert res.provider == "mock"
    assert "Check load #104" in res.content


@pytest.mark.asyncio
@pytest.mark.parametrize("provider,env_keys", [
    ("openai", ["LTA_OPENAI_API_KEY", "OPENAI_API_KEY"]),
    ("anthropic", ["ANTHROPIC_API_KEY"]),
    ("gemini", ["GEMINI_API_KEY"]),
])
async def test_call_upstream_missing_key_raises_or_falls_back(monkeypatch, provider, env_keys):
    for k in env_keys:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    with pytest.raises(UpstreamProviderError, match="Missing"):
        await call_upstream(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "hello"}],
        )

    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "true")
    res = await call_upstream(
        provider=provider,
        model="test-model",
        messages=[{"role": "user", "content": "hello"}],
    )
    assert res.provider == f"{provider}:simulated"


# ---------- call_upstream: OpenAI-compatible & Ollama ----------

@pytest.mark.asyncio
async def test_call_upstream_openai_success(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890123456")
    monkeypatch.setenv("LTA_OPENAI_BASE_URL", "https://api.openai.test/v1")

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.openai.test/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer sk-test-key-1234567890123456"
        body = json.loads(request.content.decode())
        assert body["model"] == "gpt-4o-mini"
        assert body["temperature"] == 0.2
        assert body["max_tokens"] == 128
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "Dispatch cleared."}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 3},
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        res = await call_upstream(
            provider="openai",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Status?"}],
            temperature=0.2,
            max_tokens=128,
            http_client=client,
        )
    assert res.content == "Dispatch cleared."
    assert res.provider == "openai"
    assert res.prompt_tokens == 11
    assert res.completion_tokens == 3


@pytest.mark.asyncio
async def test_call_upstream_ollama_local_no_key_required(monkeypatch):
    monkeypatch.setenv("LTA_OLLAMA_BASE_URL", "http://localhost:11434/v1")

    def handler(request: httpx.Request) -> httpx.Response:
        assert "Authorization" not in request.headers
        return httpx.Response(
            200,
            json={
                "model": "llama3.2",
                "choices": [{"message": {"content": "Local response"}}],
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        res = await call_upstream(
            provider="ollama",
            model="llama3.2",
            messages=[{"role": "user", "content": "hi"}],
            http_client=client,
        )
    assert res.content == "Local response"
    assert res.provider == "ollama"


@pytest.mark.asyncio
async def test_call_upstream_openai_empty_choices_raises(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890123456")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(UpstreamProviderError, match="empty choices"):
            await call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )


# ---------- call_upstream: Anthropic ----------

@pytest.mark.asyncio
async def test_call_upstream_anthropic_success(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-1234567890123456")

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.anthropic.com/v1/messages"
        assert request.headers["x-api-key"] == "sk-ant-test-key-1234567890123456"
        assert request.headers["anthropic-version"] == "2023-06-01"
        body = json.loads(request.content.decode())
        assert body["system"] == "Be concise"
        assert body["messages"] == [{"role": "user", "content": "Check HOS"}]
        return httpx.Response(
            200,
            json={
                "model": "claude-sonnet-4-20250514",
                "content": [{"type": "text", "text": "HOS within limits."}],
                "usage": {"input_tokens": 15, "output_tokens": 6},
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        res = await call_upstream(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            messages=[
                {"role": "system", "content": "Be concise"},
                {"role": "user", "content": "Check HOS"},
            ],
            http_client=client,
        )
    assert res.content == "HOS within limits."
    assert res.provider == "anthropic"
    assert res.prompt_tokens == 15
    assert res.completion_tokens == 6


# ---------- call_upstream: Gemini ----------

@pytest.mark.asyncio
async def test_call_upstream_gemini_success_skips_thought_parts(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaTestKey12345678901234567890")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-goog-api-key"] == "AIzaTestKey12345678901234567890"
        body = json.loads(request.content.decode())
        assert body["systemInstruction"]["parts"][0]["text"] == "Safety first"
        assert body["contents"][0]["role"] == "user"
        assert body["contents"][1]["role"] == "model"
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"thought": True, "text": "internal chain of thought"},
                                {"text": "Final answer: 42"},
                            ]
                        },
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {"promptTokenCount": 20, "candidatesTokenCount": 8},
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        res = await call_upstream(
            provider="gemini",
            model="gemini-2.5-flash",
            messages=[
                {"role": "system", "content": "Safety first"},
                {"role": "user", "content": "Q1"},
                {"role": "assistant", "content": "A1"},
                {"role": "user", "content": "Q2"},
            ],
            temperature=0.0,
            max_tokens=256,
            http_client=client,
        )
    assert res.content == "Final answer: 42"
    assert res.provider == "gemini"
    assert res.prompt_tokens == 20
    assert res.completion_tokens == 8


@pytest.mark.asyncio
async def test_call_upstream_gemini_no_candidates_and_empty_parts(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaTestKey12345678901234567890")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    def no_cand_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"candidates": []})

    transport1 = httpx.MockTransport(no_cand_handler)
    async with httpx.AsyncClient(transport=transport1) as client:
        with pytest.raises(UpstreamProviderError, match="no candidates"):
            await call_upstream(
                provider="gemini",
                model="gemini-2.5-flash",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )

    def empty_parts_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": []}, "finishReason": "SAFETY"}]},
        )

    transport2 = httpx.MockTransport(empty_parts_handler)
    async with httpx.AsyncClient(transport=transport2) as client:
        with pytest.raises(UpstreamProviderError, match="finishReason=SAFETY"):
            await call_upstream(
                provider="gemini",
                model="gemini-2.5-flash",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )


# ---------- HTTP & Transport Errors + Secret Scrubbing ----------

@pytest.mark.asyncio
async def test_call_upstream_http_status_error_scrubs_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890123456")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"message": "Invalid key sk-leakedsecret1234567890"}},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(UpstreamProviderError) as exc_info:
            await call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )
    msg = str(exc_info.value)
    assert "HTTP 401" in msg
    assert "sk-leakedsecret1234567890" not in msg
    assert "[REDACTED_SECRET]" in msg


@pytest.mark.asyncio
async def test_call_upstream_http_error_and_fallback(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890123456")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom ghp_1234567890abcdefghij12", request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(UpstreamProviderError) as exc_info:
            await call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )
    assert "ghp_1234567890abcdefghij12" not in str(exc_info.value)
    assert "[REDACTED_SECRET]" in str(exc_info.value)

    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "true")
    async with httpx.AsyncClient(transport=transport) as client:
        res = await call_upstream(
            provider="openai",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hi"}],
            http_client=client,
        )
    assert res.provider == "openai:simulated"


@pytest.mark.asyncio
async def test_call_upstream_unsupported_provider(monkeypatch):
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")
    with pytest.raises(UpstreamProviderError, match="Unsupported upstream provider"):
        await call_upstream(
            provider="unknown_vendor",
            model="m1",
            messages=[{"role": "user", "content": "hi"}],
        )