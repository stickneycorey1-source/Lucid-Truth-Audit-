import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import shadow


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv(
        "LTA_TENANT_KEYS",
        json.dumps({"pilot_acme": "test-secret-key-123"}),
    )
    app = FastAPI()
    app.include_router(shadow.router)
    return TestClient(app)


def test_shadow_ingest_rejects_missing_auth(client: TestClient) -> None:
    resp = client.post("/v1/shadow/ingest", json={"prompt": "hello"})
    assert resp.status_code == 401


def test_shadow_ingest_rejects_invalid_key(client: TestClient) -> None:
    resp = client.post(
        "/v1/shadow/ingest",
        headers={"Authorization": "Bearer wrong-key"},
        json={"prompt": "hello"},
    )
    assert resp.status_code == 401


def test_shadow_ingest_returns_202_and_logs_zero_retention_audit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[shadow.ZeroRetentionAuditRecord] = []
    monkeypatch.setattr(shadow, "write_audit_record", captured.append)

    secret_prompt = "SSN 123-45-6789 \u202e p\u0430ssword"
    resp = client.post(
        "/v1/shadow/ingest",
        headers={"Authorization": "Bearer test-secret-key-123"},
        json={
            "prompt": secret_prompt,
            "request_id": "req-999",
            "model_target": "gpt-4o",
            "metadata": {"env": "staging"},
        },
    )

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["tenant_id"] == "pilot_acme"
    assert body["audit_id"].startswith("aud_")
    assert len(body["input_sha256"]) == 64

    # Verify background task ran and captured zero-retention record
    assert len(captured) == 1
    record = captured[0]
    assert record.audit_id == body["audit_id"]
    assert record.tenant_id == "pilot_acme"
    assert record.bidi_override_detected is True
    assert record.homoglyphs_detected is True
    assert "BIDI_OVERRIDE" in record.risk_flags
    assert "MIXED_SCRIPT_HOMOGLYPH" in record.risk_flags

    # Hard zero-retention guarantee: raw PII/prompt must never appear in audit JSON
    serialized = record.model_dump_json()
    assert "123-45-6789" not in serialized
    assert "password" not in serialized
    assert secret_prompt not in serialized
