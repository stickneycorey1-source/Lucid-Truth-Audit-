"""Unit tests for lta/providers.py (v2.4.1) covering providers, fallbacks, and error scrubbing."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import httpx
import pytest

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


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: Optional[Dict[str, Any]] = None,
        text: str = "",
        url: str = "https://example.test",
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.text = text
        self.request = httpx.Request("POST", url)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            resp = httpx.Response(
                self.status_code,
                json=self._json_data if self._json_data else None,
                text=self.text or None,
                request=self.request,
            )
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=self.request,
                response=resp,
            )

    def json(self) -> Dict[str, Any]:
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, handler, **kwargs) -> None:
        self._handler = handler
        self.kwargs = kwargs

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> _FakeResponse:
        return await self._handler(url, headers=headers, payload=json or {}, timeout=timeout)


def test_scrub_secrets_and_url_validation():
    raw = "sk-1234567890abcdef12 and AIzaSy1234567890abcdefghij"
    scrubbed = _scrub_secrets(raw)
    assert "sk-1234567890abcdef12" not in scrubbed
    assert "AIzaSy1234567890abcdefghij" not in scrubbed
    assert scrubbed.count("[REDACTED_SECRET]") == 2

    assert validate_upstream_url("https://api.openai.com/v1/") == "https://api.openai.com/v1"
    assert validate_upstream_url("http://localhost:11434/v1/") == "http://localhost:11434/v1"
    with pytest.raises(UpstreamProviderError):
        validate_upstream_url("http://api.openai.com/v1")


def test_fallback_and_mock_simulation_variants(monkeypatch):
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "true")
    assert _fallback_enabled() is True
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")
    assert _fallback_enabled() is False

    for marker, needle in [
        ("__simulate_leak_system__", "Internal System Instructions"),
        ("__simulate_leak_ssn__", "123-45-6789"),
        ("__simulate_leak_secret__", "sk-prod1234567890abcdef1234"),
        ("Load #882 dispatch check", "[LTA Verified Upstream Response]"),
    ]:
        out = _simulate_mock_response(
            model="lta-mock",
            provider_label="mock",
            messages=[{"role": "user", "content": marker}],
        )
        assert isinstance(out, ProviderResponse)
        assert needle in out.content


def test_post_json_and_provider_adapters(monkeypatch):
    async def run_all() -> None:
        # 1. _post_json with explicit client and fallback client
        async def ok_handler(url, *, headers, payload, timeout):
            return _FakeResponse(status_code=200, json_data={"url": url, "echo": payload}, url=url)

        client = _FakeAsyncClient(ok_handler)
        res_json = await _post_json(
            "https://example.test/v1/echo",
            headers={"x-custom": "yes"},
            payload={"k": "v"},
            timeout_s=5.0,
            http_client=client,
        )
        assert res_json["echo"] == {"k": "v"}

        monkeypatch.setattr(
            providers.httpx,
            "AsyncClient",
            lambda **kwargs: _FakeAsyncClient(ok_handler, **kwargs),
        )
        res_auto = await _post_json(
            "https://example.test/v1/auto",
            payload={"ping": 1},
            timeout_s=5.0,
            http_client=None,
        )
        assert res_auto["echo"] == {"ping": 1}

        # 2. Mock provider
        mock_res = await call_upstream(
            provider="mock",
            model="lta-mock",
            messages=[{"role": "user", "content": "Hello P2"}],
        )
        assert mock_res.provider == "mock"

        # 3. OpenAI success
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890123456")
        monkeypatch.setenv("LTA_OPENAI_BASE_URL", "https://api.openai.test/v1")

        async def openai_handler(url, *, headers, payload, timeout):
            assert url == "https://api.openai.test/v1/chat/completions"
            assert headers["Authorization"] == "Bearer sk-test-key-1234567890123456"
            return _FakeResponse(
                status_code=200,
                json_data={
                    "model": "gpt-4o-mini",
                    "choices": [{"message": {"content": "Route clear"}}],
                    "usage": {"prompt_tokens": 9, "completion_tokens": 2},
                },
                url=url,
            )

        oai_res = await call_upstream(
            provider="openai",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Check route"}],
            temperature=0.1,
            max_tokens=64,
            http_client=_FakeAsyncClient(openai_handler),
        )
        assert oai_res.content == "Route clear"
        assert oai_res.prompt_tokens == 9

        # 4. Anthropic success
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-key-1234567890123456")

        async def anthropic_handler(url, *, headers, payload, timeout):
            assert url == "https://api.anthropic.com/v1/messages"
            assert payload["system"] == "System rule"
            return _FakeResponse(
                status_code=200,
                json_data={
                    "model": "claude-sonnet-4-20250514",
                    "content": [{"type": "text", "text": "Compliant"}],
                    "usage": {"input_tokens": 12, "output_tokens": 3},
                },
                url=url,
            )

        anth_res = await call_upstream(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            messages=[
                {"role": "system", "content": "System rule"},
                {"role": "user", "content": "Check HOS"},
            ],
            http_client=_FakeAsyncClient(anthropic_handler),
        )
        assert anth_res.content == "Compliant"
        assert anth_res.completion_tokens == 3

        # 5. Gemini success (filters thought parts)
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaTestKey12345678901234567890")

        async def gemini_handler(url, *, headers, payload, timeout):
            assert "generateContent" in url
            assert headers["x-goog-api-key"] == "AIzaTestKey12345678901234567890"
            return _FakeResponse(
                status_code=200,
                json_data={
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {"thought": True, "text": "hidden reasoning"},
                                    {"text": "Verified safe"},
                                ]
                            },
                            "finishReason": "STOP",
                        }
                    ],
                    "usageMetadata": {"promptTokenCount": 14, "candidatesTokenCount": 4},
                },
                url=url,
            )

        gem_res = await call_upstream(
            provider="gemini",
            model="gemini-2.5-flash",
            messages=[
                {"role": "system", "content": "Guard"},
                {"role": "user", "content": "Prompt"},
                {"role": "assistant", "content": "Prior reply"},
            ],
            http_client=_FakeAsyncClient(gemini_handler),
        )
        assert gem_res.content == "Verified safe"
        assert gem_res.prompt_tokens == 14

        # 6. HTTP error scrubs secrets
        monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

        async def err_handler(url, *, headers, payload, timeout):
            return _FakeResponse(
                status_code=401,
                json_data={"error": {"message": "Bad key sk-leaked9999999999999999"}},
                url=url,
            )

        with pytest.raises(UpstreamProviderError) as exc_info:
            await call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hi"}],
                http_client=_FakeAsyncClient(err_handler),
            )
        assert "sk-leaked9999999999999999" not in str(exc_info.value)
        assert "[REDACTED_SECRET]" in str(exc_info.value)

        # 7. Missing key -> simulated fallback when enabled
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "true")
        fb_res = await call_upstream(
            provider="gemini",
            model="gemini-2.5-flash",
            messages=[{"role": "user", "content": "Fallback check"}],
        )
        assert fb_res.provider == "gemini:simulated"

    asyncio.run(run_all())