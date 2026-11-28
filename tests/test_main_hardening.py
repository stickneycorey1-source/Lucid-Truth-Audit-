"""Unit tests covering hardening changes in app/main.py."""

from __future__ import annotations

import time
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.main as main_mod
import app.security as security_mod
from app.main import (
    PAN_RE,
    GuardRequest,
    RequestBodyLimitMiddleware,
    _sanitize_header_value,
    redact_sensitive_entities,
    sanitize_csv_cell,
)


@pytest.fixture(autouse=True)
def _clean_env_and_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LUCID_TENANT_KEYS", raising=False)
    monkeypatch.setenv("LUCID_AUDIT_API_KEY", "test-main-key")
    security_mod.rate_limiter.reset()


# ---------------------------------------------------------------------------
# 1. RequestBodyLimitMiddleware registration & 413 enforcement
# ---------------------------------------------------------------------------


def test_request_body_limit_middleware_is_registered_on_app() -> None:
    assert any(
        mw.cls is RequestBodyLimitMiddleware for mw in main_mod.app.user_middleware
    )


def _make_limited_client(max_bytes: int = 64) -> TestClient:
    mini_app = FastAPI()

    @mini_app.post("/echo")
    async def _echo(payload: dict) -> dict:
        return payload

    mini_app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=max_bytes)
    return TestClient(mini_app)


def test_body_limit_allows_payload_within_cap() -> None:
    client = _make_limited_client(max_bytes=128)
    resp = client.post("/echo", json={"msg": "ok"})
    assert resp.status_code == 200
    assert resp.json() == {"msg": "ok"}


def test_body_limit_rejects_oversized_content_length_and_sets_security_headers() -> None:
    client = _make_limited_client(max_bytes=32)
    resp = client.post(
        "/echo",
        content=b"{" + b"a" * 64 + b"}",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json()["detail"]["vector"] == "ingress.body_too_large"
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    # Fallback UUID generated when X-Request-ID is absent
    uuid.UUID(resp.headers["x-request-id"])


def test_body_limit_rejects_streamed_oversized_body_with_invalid_content_length() -> None:
    client = _make_limited_client(max_bytes=32)
    resp = client.post(
        "/echo",
        content=b'{"data":"' + b"x" * 64 + b'"}',
        headers={
            "Content-Type": "application/json",
            "Content-Length": "not-a-number",
            "X-Request-ID": "req-123",
        },
    )
    assert resp.status_code == 413
    assert resp.headers["x-request-id"] == "req-123"


def test_sanitize_header_value_strips_crlf_and_truncates() -> None:
    assert _sanitize_header_value("abc\r\nX-Injected: 1", "fallback") == "abcX-Injected: 1"
    assert _sanitize_header_value("   \r\n  ", "fallback") == "fallback"
    assert len(_sanitize_header_value("x" * 300, "fallback")) == 128


# ---------------------------------------------------------------------------
# 2. ReDoS-safe PAN_RE & modern SECRET_RE
# ---------------------------------------------------------------------------


def test_pan_regex_is_linear_time_on_adversarial_input() -> None:
    adversarial = "1" + (" " * 40 + "1") * 25 + "!"
    started = time.perf_counter()
    matches = PAN_RE.findall(adversarial)
    elapsed = time.perf_counter() - started

    assert matches == []
    assert elapsed < 0.05


@pytest.mark.parametrize(
    "secret",
    [
        "sk-proj-AbCdEf123456_7890-xyz987",
        "sk-ant-api03-9988776655_aabbcc-dd11",
        "ghp_1234567890abcdefghij123456",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyD-1234567890_abcdef1234",
    ],
)
def test_redact_sensitive_entities_catches_modern_secrets(secret: str) -> None:
    cleaned, types = redact_sensitive_entities(f"token={secret}")
    assert secret not in cleaned
    assert "[REDACTED_SECRET]" in cleaned
    assert "API_SECRET" in types


def test_redact_sensitive_entities_luhn_pan_and_ssn() -> None:
    cleaned, types = redact_sensitive_entities(
        "SSN 123-45-6789 card 4111-1111-1111-1111 bad 4111-1111-1111-1112"
    )
    assert "[REDACTED_SSN]" in cleaned
    assert "[REDACTED_PAN]" in cleaned
    assert "4111-1111-1111-1112" in cleaned
    assert set(types) == {"SSN", "PAN"}


# ---------------------------------------------------------------------------
# 3. Bounded limit query params & GuardRequest.messages cap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", ["/api/v1/evidence", "/api/v1/audit/ledger"])
@pytest.mark.parametrize("bad_limit", [0, -5, 1001])
def test_list_endpoints_reject_out_of_range_limit(endpoint: str, bad_limit: int) -> None:
    client = TestClient(main_mod.app)
    resp = client.get(
        endpoint,
        params={"limit": bad_limit},
        headers={"X-API-Key": "test-main-key"},
    )
    assert resp.status_code == 422


def test_guard_request_rejects_more_than_50_messages() -> None:
    too_many_turns = [{"role": "user", "content": f"turn {i}"} for i in range(51)]
    with pytest.raises(ValueError):
        GuardRequest(prompt="hello", messages=too_many_turns)


# ---------------------------------------------------------------------------
# 4. CSV export filename sanitization & formula-injection neutralization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("=CMD|' /C calc'!A0", "'=CMD|' /C calc'!A0"),
        ("+SUM(A1:A2)", "'+SUM(A1:A2)"),
        ("-1+1", "'-1+1"),
        ("@SUM(1,2)", "'@SUM(1,2)"),
        ("normal_text", "normal_text"),
    ],
)
def test_sanitize_csv_cell_neutralizes_formulas(raw: str, expected: str) -> None:
    assert sanitize_csv_cell(raw) == expected


def test_export_csv_sanitizes_tenant_id_in_content_disposition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCID_TENANT_KEYS", '../evil"tenant;name:dirty-key:never')
    client = TestClient(main_mod.app)

    resp = client.get(
        "/api/v1/audit/export.csv",
        headers={"X-API-Key": "dirty-key"},
    )
    assert resp.status_code == 200
    disposition = resp.headers["content-disposition"]
    assert disposition == 'attachment; filename="lucid_audit_.._evil_tenant_name.csv"'
    assert ";" not in disposition.split('filename="', 1)[1]