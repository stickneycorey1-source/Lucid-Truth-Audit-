"""Unit tests covering ingress, PII redaction, and CSV hardening in app/main.py."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.ledger as ledger_mod
import app.security as security_mod
from app.main import app, sanitize_csv_cell


@pytest.fixture(autouse=True)
def _setup_app_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("LUCID_TENANT_KEYS", raising=False)
    monkeypatch.setenv("LUCID_AUDIT_API_KEY", "main-hardening-key")
    monkeypatch.setenv("LUCID_MAX_BODY_BYTES", "1024")
    security_mod.rate_limiter.reset()
    ledger_mod.audit_ledger.reconfigure(str(tmp_path / "main_hardening.db"))


def test_health_and_security_headers() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "no-referrer"


def test_guard_rejects_missing_or_invalid_api_key() -> None:
    client = TestClient(app)
    r1 = client.post("/api/v1/guard", json={"prompt": "hello"})
    assert r1.status_code in (401, 403)

    r2 = client.post(
        "/api/v1/guard",
        json={"prompt": "hello"},
        headers={"X-API-Key": "wrong-key"},
    )
    assert r2.status_code in (401, 403)


def test_guard_redacts_ssn_and_api_keys() -> None:
    client = TestClient(app)
    resp = client.post(
        "/api/v1/guard",
        json={"prompt": "Driver SSN 123-45-6789 and key sk-proj-abcdef1234567890"},
        headers={"X-API-Key": "main-hardening-key"},
    )
    assert resp.status_code == 200
    raw_text = resp.text
    assert "123-45-6789" not in raw_text
    assert "sk-proj-abcdef1234567890" not in raw_text


@pytest.mark.parametrize("dangerous", ["=cmd|'/C calc'!A0", "+SUM(A1:A2)", "-1+1", "@IMPORTXML(A1)"])
def test_csv_formula_injection_neutralized(dangerous: str) -> None:
    sanitized = sanitize_csv_cell(dangerous)
    assert not sanitized.startswith(("=", "+", "-", "@"))


def test_request_body_limit_returns_413(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCID_MAX_BODY_BYTES", "64")
    client = TestClient(app)
    resp = client.post(
        "/api/v1/guard",
        json={"prompt": "x" * 500},
        headers={"X-API-Key": "main-hardening-key"},
    )
    assert resp.status_code == 413