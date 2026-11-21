"""Provider-agnostic upstream LLM adapters (Hardened v2.4 — full Gemini support + safe diagnostics)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama"}


@dataclass
class ProviderResponse:
    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class UpstreamProviderError(RuntimeError):
    """Raised when an upstream LLM provider call fails or is misconfigured."""


def validate_upstream_url(url: str) -> str:
    """Enforce HTTPS on all non-localhost upstream provider endpoints."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https":
        return url.rstrip("/")
    if parsed.scheme == "http" and host in _LOCAL_HOSTS:
        return url.rstrip("/")
    raise UpstreamProviderError(
        f"Refusing insecure non-local upstream URL scheme '{parsed.scheme}' for host '{host}'."
    )


async def _post_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    payload: Dict[str, Any],
    timeout_s: float,
    http_client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    if http_client is not None:
        resp = await http_client.post(url, headers=headers, json=payload, timeout=timeout_s)
        resp.raise_for_status()
        return resp.json()
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()


async def call_upstream(
    *,
    provider: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    timeout_s: float = 30.0,
    http_client: Optional[httpx.AsyncClient] = None,
) -> ProviderResponse:
    """Route sanitized chat messages to the configured upstream AI provider."""
    provider_key = provider.lower().strip()
    model = model.strip()

    if provider_key == "mock":
        last_user = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"), ""
        )
        if "__simulate_leak_system__" in last_user:
            return ProviderResponse(
                content="Internal System Instructions: You are a confidential enterprise assistant.",
                model=model,
                provider="mock",
            )
        if "__simulate_leak_ssn__" in last_user:
            return ProviderResponse(
                content="Customer SSN on file is 123-45-6789.",
                model=model,
                provider="mock",
            )
        if "__simulate_leak_secret__" in last_user:
            return ProviderResponse(
                content="Upstream token: sk-prod1234567890abcdef1234",
                model=model,
                provider="mock",
            )
        return ProviderResponse(
            content=f"[LTA Verified Upstream Response] Processed request cleanly: {last_user[:160]}",
            model=model,
            provider="mock",
            prompt_tokens=max(1, len(last_user) // 4),
            completion_tokens=24,
        )

    try:
        if provider_key in ("openai", "azure_openai", "vllm", "ollama"):
            raw_url = os.getenv(
                f"LTA_{provider_key.upper()}_BASE_URL",
                "http://localhost:11434/v1"
                if provider_key == "ollama"
                else "https://api.openai.com/v1",
            )
            base_url = validate_upstream_url(raw_url)
            api_key = (
                os.getenv(f"LTA_{provider_key.upper()}_API_KEY")
                or os.getenv("OPENAI_API_KEY", "")
            ).strip()
            if provider_key in ("openai", "azure_openai") and not api_key:
                raise UpstreamProviderError(
                    f"Missing API key for upstream provider '{provider_key}'"
                )
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            payload: Dict[str, Any] = {"model": model, "messages": messages}
            if temperature is not None:
                payload["temperature"] = temperature
            if max_tokens is not None:
                payload["max_tokens"] = max_tokens

            data = await _post_json(
                f"{base_url}/chat/completions",
                headers=headers,
                payload=payload,
                timeout_s=timeout_s,
                http_client=http_client,
            )
            choices = data.get("choices") or []
            if not choices or not isinstance(choices[0], dict):
                raise UpstreamProviderError(f"Upstream '{provider_key}' returned empty choices")
            content = (choices[0].get("message") or {}).get("content", "")
            usage = data.get("usage") or {}
            return ProviderResponse(
                content=str(content),
                model=str(data.get("model", model)),
                provider=provider_key,
                prompt_tokens=int(usage.get("prompt_tokens", 0)),
                completion_tokens=int(usage.get("completion_tokens", 0)),
            )

        if provider_key == "anthropic":
            api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
            if not api_key:
                raise UpstreamProviderError("Missing ANTHROPIC_API_KEY")
            system_parts = [m["content"] for m in messages if m.get("role") == "system"]
            chat_msgs = [m for m in messages if m.get("role") != "system"]
            payload = {
                "model": model,
                "max_tokens": max_tokens or 1024,
                "messages": chat_msgs,
            }
            if temperature is not None:
                payload["temperature"] = temperature
            if system_parts:
                payload["system"] = "\n".join(system_parts)
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            data = await _post_json(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                payload=payload,
                timeout_s=timeout_s,
                http_client=http_client,
            )
            text_blocks = [
                b.get("text", "")
                for b in data.get("content", [])
                if isinstance(b, dict) and b.get("type") == "text"
            ]
            usage = data.get("usage") or {}
            return ProviderResponse(
                content="".join(text_blocks),
                model=str(data.get("model", model)),
                provider="anthropic",
                prompt_tokens=int(usage.get("input_tokens", 0)),
                completion_tokens=int(usage.get("output_tokens", 0)),
            )

        if provider_key == "gemini":
            api_key = os.getenv("GEMINI_API_KEY", "").strip()
            if not api_key:
                raise UpstreamProviderError("Missing GEMINI_API_KEY")
            system_parts = [m["content"] for m in messages if m.get("role") == "system"]
            contents = [
                {
                    "role": "model" if m.get("role") == "assistant" else "user",
                    "parts": [{"text": m["content"]}],
                }
                for m in messages
                if m.get("role") != "system"
            ]
            gem_payload: Dict[str, Any] = {"contents": contents}
            if system_parts:
                gem_payload["systemInstruction"] = {
                    "parts": [{"text": "\n".join(system_parts)}]
                }
            gen_cfg: Dict[str, Any] = {}
            if temperature is not None:
                gen_cfg["temperature"] = temperature
            if max_tokens is not None:
                gen_cfg["maxOutputTokens"] = max_tokens
            if gen_cfg:
                gem_payload["generationConfig"] = gen_cfg

            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{model}:generateContent"
            )
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            }
            data = await _post_json(
                url,
                headers=headers,
                payload=gem_payload,
                timeout_s=timeout_s,
                http_client=http_client,
            )
            candidates = data.get("candidates") or []
            if not candidates or not isinstance(candidates[0], dict):
                raise UpstreamProviderError(
                    f"Upstream 'gemini' returned no candidates ({model})"
                )
            parts = (candidates[0].get("content") or {}).get("parts") or []
            if not parts:
                finish = candidates[0].get("finishReason", "UNKNOWN")
                raise UpstreamProviderError(
                    f"Upstream 'gemini' returned empty content (finishReason={finish})"
                )
            text = "".join(
                p.get("text", "")
                for p in parts
                if isinstance(p, dict) and not p.get("thought")
            )
            usage = data.get("usageMetadata") or {}
            return ProviderResponse(
                content=text,
                model=model,
                provider="gemini",
                prompt_tokens=int(usage.get("promptTokenCount", 0)),
                completion_tokens=int(usage.get("candidatesTokenCount", 0)),
            )
    except httpx.HTTPStatusError as exc:
        err_msg = ""
        try:
            body = exc.response.json()
            err_msg = body.get("error", {}).get("message", "") if isinstance(body, dict) else ""
        except Exception:
            err_msg = exc.response.text[:200]
        raise UpstreamProviderError(
            f"Upstream '{provider_key}' HTTP {exc.response.status_code} ({model}): {err_msg or 'request rejected'}"
        ) from exc
    except httpx.HTTPError as exc:
        raise UpstreamProviderError(
            f"Upstream '{provider_key}' {type(exc).__name__} ({model}): {exc or 'connection or timeout error'}"
        ) from exc

    raise UpstreamProviderError(f"Unsupported upstream provider: '{provider}'")