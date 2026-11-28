"""Unit tests covering hardening changes in lta/providers.py and lta/audit_ledger.py."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict

import httpx
import pytest

from lta.audit_ledger import AuditLedger, _safe_latency
from lta.providers import UpstreamProviderError, _scrub_secrets, call_upstream


# ---------------------------------------------------------------------------
# lta/providers.py hardening tests
# ---------------------------------------------------------------------------


def test_scrub_secrets_redacts_modern_hyphenated_keys() -> None:
    raw = (
        "OpenAI sk-proj-AbCdEf123456_7890-xyz "
        "Anthropic sk-ant-api03-9988776655_aabbcc-dd "
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 "
        "Google AIzaSyD-1234567890abcdef12345"
    )
    scrubbed = _scrub_secrets(raw)
    assert "sk-proj-" not in scrubbed
    assert "sk-ant-" not in scrubbed
    assert "eyJhbGci" not in scrubbed
    assert "AIzaSyD" not in scrubbed
    assert scrubbed.count("[REDACTED_SECRET]") == 4


@pytest.mark.parametrize(
    "bad_model",
    [
        "../v1/models/secret",
        "gemini-2.0-flash?key=injected",
        "gemini-2.0-flash#fragment",
        "gemini 2.0",
        "",
    ],
)
def test_gemini_rejects_path_injection_model_id(
    monkeypatch: pytest.MonkeyPatch, bad_model: str
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyTestKey123456789012345")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    with pytest.raises(UpstreamProviderError, match="Invalid Gemini model identifier"):
        asyncio.run(
            call_upstream(
                provider="gemini",
                model=bad_model,
                messages=[{"role": "user", "content": "hi"}],
            )
        )


@pytest.mark.parametrize(
    "response,expected_msg",
    [
        (
            httpx.Response(200, text="<html>502 Bad Gateway</html>"),
            "invalid JSON",
        ),
        (
            httpx.Response(200, json=["not", "a", "dict"]),
            "non-object JSON",
        ),
    ],
)
def test_post_json_rejects_non_json_and_non_dict_200(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    expected_msg: str,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-test1234567890abcdef")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    transport = httpx.MockTransport(lambda _req: response)

    async def _run() -> None:
        async with httpx.AsyncClient(transport=transport) as client:
            await call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hello"}],
                http_client=client,
            )

    with pytest.raises(UpstreamProviderError, match=expected_msg):
        asyncio.run(_run())


def test_post_json_retries_transient_502_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-test1234567890abcdef")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("lta.providers.asyncio.sleep", _no_sleep)

    attempts = {"count": 0}

    def _handler(_req: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return httpx.Response(502, text="temporary gateway error")
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "recovered"}}],
                "usage": {"prompt_tokens": None, "completion_tokens": None},
            },
        )

    async def _run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            return await call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "ping"}],
                http_client=client,
            )

    res = asyncio.run(_run())
    assert attempts["count"] == 2
    assert res.content == "recovered"
    assert res.prompt_tokens == 0
    assert res.completion_tokens == 0


def test_anthropic_malformed_content_and_null_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-test1234567890")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    bad_transport = httpx.MockTransport(
        lambda _req: httpx.Response(200, json={"content": "not-a-list"})
    )

    async def _run_bad() -> None:
        async with httpx.AsyncClient(transport=bad_transport) as client:
            await call_upstream(
                provider="anthropic",
                model="claude-3-5-sonnet",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )

    with pytest.raises(UpstreamProviderError, match="malformed content"):
        asyncio.run(_run_bad())

    ok_transport = httpx.MockTransport(
        lambda _req: httpx.Response(
            200,
            json={
                "model": None,
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": None, "output_tokens": None},
            },
        )
    )

    async def _run_ok():
        async with httpx.AsyncClient(transport=ok_transport) as client:
            return await call_upstream(
                provider="anthropic",
                model="claude-3-5-sonnet",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )

    res = asyncio.run(_run_ok())
    assert res.content == "ok"
    assert res.model == "claude-3-5-sonnet"
    assert res.prompt_tokens == 0
    assert res.completion_tokens == 0


def test_http_status_error_scrubs_secrets_and_handles_string_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-secret_value_1234567890")
    monkeypatch.setenv("LTA_ALLOW_SIMULATED_FALLBACK", "false")

    transport = httpx.MockTransport(
        lambda _req: httpx.Response(
            401,
            json={"error": "Rejected key sk-proj-secret_value_1234567890"},
        )
    )

    async def _run() -> None:
        async with httpx.AsyncClient(transport=transport) as client:
            await call_upstream(
                provider="openai",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hi"}],
                http_client=client,
            )

    with pytest.raises(UpstreamProviderError) as exc_info:
        asyncio.run(_run())

    msg = str(exc_info.value)
    assert "sk-proj-secret_value" not in msg
    assert "[REDACTED_SECRET]" in msg


# ---------------------------------------------------------------------------
# lta/audit_ledger.py hardening tests
# ---------------------------------------------------------------------------


def _record_sample(ledger: AuditLedger, **overrides: Any):
    params: Dict[str, Any] = {
        "tenant_id": "tenant-a",
        "endpoint": "/v1/chat/completions",
        "policy_pack": "general_enterprise",
        "provider": "mock",
        "action": "ALLOW",
        "http_status": 200,
        "vector": None,
        "redactions": [],
        "raw_payload_for_digest": "hello world",
        "latency_ms": 12.345,
        "policy_version": "2.4.0",
        "policy_sha256": "a" * 64,
        "config_fingerprint": "b" * 64,
        "request_id": "req-001",
    }
    params.update(overrides)
    return ledger.record(**params)


def test_sqlite_wal_mode_enabled_for_file_db(tmp_path: Path) -> None:
    db_file = tmp_path / "audit.db"
    ledger = AuditLedger(f"sqlite:///{db_file}")
    try:
        conn = sqlite3.connect(db_file)
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert str(mode).lower() == "wal"
        finally:
            conn.close()
    finally:
        ledger.close()


def test_extra_provenance_sanitized_and_cannot_clobber_core_fields() -> None:
    ledger = AuditLedger("sqlite:///:memory:")
    try:
        rec = _record_sample(
            ledger,
            extra_provenance={
                "tags": {"beta", "alpha"},
                "policy_sha256": "tampered",
                "config_fingerprint": "tampered",
                "request_id": "tampered",
            },
        )
        parsed = json.loads(rec.provenance_json)
        assert parsed["tags"] == ["alpha", "beta"]
        assert parsed["policy_sha256"] == "a" * 64
        assert parsed["config_fingerprint"] == "b" * 64
        assert parsed["request_id"] == "req-001"
        assert ledger.verify_chain() == (True, 1, None)
    finally:
        ledger.close()


def test_verify_chain_detects_tampered_provenance_hash(tmp_path: Path) -> None:
    db_file = tmp_path / "tamper.db"
    ledger = AuditLedger(f"sqlite:///{db_file}")
    try:
        _record_sample(ledger, request_id="req-1")
        _record_sample(ledger, request_id="req-2")
        assert ledger.verify_chain() == (True, 2, None)

        conn = sqlite3.connect(db_file)
        try:
            conn.execute(
                "UPDATE audit_events SET provenance_hash = ? WHERE seq_id = 2",
                ("f" * 64,),
            )
            conn.commit()
        finally:
            conn.close()

        valid, total, broken_seq = ledger.verify_chain()
        assert valid is False
        assert total == 2
        assert broken_seq == 2
    finally:
        ledger.close()


def test_non_finite_and_negative_latency_clamped_in_record_and_export() -> None:
    assert _safe_latency(float("nan")) == 0.0
    assert _safe_latency(float("inf")) == 0.0
    assert _safe_latency(-4.2) == 0.0

    ledger = AuditLedger("sqlite:///:memory:")
    try:
        r1 = _record_sample(ledger, latency_ms=float("nan"), request_id="r-nan")
        r2 = _record_sample(ledger, latency_ms=float("inf"), request_id="r-inf")
        r3 = _record_sample(ledger, latency_ms=-10.0, request_id="r-neg")

        assert r1.latency_ms == 0.0
        assert r2.latency_ms == 0.0
        assert r3.latency_ms == 0.0
        assert ledger.verify_chain() == (True, 3, None)

        ndjson = ledger.export_jsonl()
        lines = [line for line in ndjson.splitlines() if line.strip()]
        assert len(lines) == 3

        def _reject_non_finite(val: str) -> None:
            raise ValueError(f"Non-standard JSON constant: {val}")

        for line in lines:
            parsed = json.loads(line, parse_constant=_reject_non_finite)
            assert parsed["latency_ms"] == 0.0
    finally:
        ledger.close()


def test_closed_ledger_raises_runtime_error() -> None:
    ledger = AuditLedger("sqlite:///:memory:")
    ledger.close()

    assert ledger.ping() is False

    with pytest.raises(RuntimeError, match="AuditLedger is closed"):
        _record_sample(ledger)

    with pytest.raises(RuntimeError, match="AuditLedger is closed"):
        ledger.record_snapshot(
            config_fingerprint="c" * 64,
            policy_name="general_enterprise",
            policy_version="2.4.0",
            policy_sha256="a" * 64,
        )

    with pytest.raises(RuntimeError, match="AuditLedger is closed"):
        ledger.verify_chain()

    with pytest.raises(RuntimeError, match="AuditLedger is closed"):
        ledger.export_jsonl()