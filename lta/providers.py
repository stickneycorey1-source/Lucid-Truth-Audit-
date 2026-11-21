"""Provider-agnostic upstream LLM adapters (OpenAI, Anthropic, Gemini, Ollama/vLLM, Mock)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx


@dataclass
class ProviderResponse:
    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class UpstreamProviderError(RuntimeError):
    """Raised when an upstream LLM provider call fails or is misconfigured."""


async def call_upstream(
    *,
    provider: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    timeout_s: float = 30.0,
) -> ProviderResponse:
    """Route sanitized chat messages to the configured upstream AI provider."""
    provider_key = provider.lower().strip()

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

    if provider_key in ("openai", "azure_openai", "vllm", "ollama"):
        base_url = os.getenv(
            f"LTA_{provider_key.upper()}_BASE_URL",
            "http://localhost:11434/v1"
            if provider_key == "ollama"
            else "https://api.openai.com/v1",
        ).rstrip("/")
        api_key = os.getenv(f"LTA_{provider_key.upper()}_API_KEY") or os.getenv(
            "OPENAI_API_KEY", ""
        )
        if provider_key in ("openai", "azure_openai") and not api_key:
            raise UpstreamProviderError(
                f"Missing API key for upstream provider '{provider_key}'"
            )
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload: Dict[str, object] = {"model": model, "messages": messages}
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(
                f"{base_url}/chat/completions", headers=headers, json=payload
            )
            resp.raise_for_status()
            data = resp.json()
        usage = data.get("usage", {})
        return ProviderResponse(
            content=data["choices"][0]["message"]["content"],
            model=data.get("model", model),
            provider=provider_key,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
        )

    if provider_key == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise UpstreamProviderError("Missing ANTHROPIC_API_KEY")
        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        chat_msgs = [m for m in messages if m.get("role") != "system"]
        payload = {
            "model": model,
            "max_tokens": max_tokens or 1024,
            "messages": chat_msgs,
        }
        if system_parts:
            payload["system"] = "\n".join(system_parts)
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages", headers=headers, json=payload
            )
            resp.raise_for_status()
            data = resp.json()
        text_blocks = [
            b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
        ]
        usage = data.get("usage", {})
        return ProviderResponse(
            content="".join(text_blocks),
            model=data.get("model", model),
            provider="anthropic",
            prompt_tokens=int(usage.get("input_tokens", 0)),
            completion_tokens=int(usage.get("output_tokens", 0)),
        )

    if provider_key == "gemini":
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            raise UpstreamProviderError("Missing GEMINI_API_KEY")
        contents = [
            {
                "role": "model" if m.get("role") == "assistant" else "user",
                "parts": [{"text": m["content"]}],
            }
            for m in messages
            if m.get("role") != "system"
        ]
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(url, json={"contents": contents})
            resp.raise_for_status()
            data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return ProviderResponse(content=text, model=model, provider="gemini")

    raise UpstreamProviderError(f"Unsupported upstream provider: '{provider}'")
