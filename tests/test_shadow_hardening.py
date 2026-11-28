"""Unit tests covering zero-retention shadow ingestion in app/api/shadow.py."""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.shadow import router as shadow_router


@pytest.fixture
def shadow_client() -> TestClient:
    app = FastAPI()
    app.include_router(shadow_router)
    return TestClient(app)


def test_shadow_ingest_fails_closed_when_tenant_keys_missing(
    monkeypatch: pytest.MonkeyPatch, shadow_client: TestClient
) -> None:
    monkeypatch.delenv("LTA_TENANT_KEYS", raising=False)
    resp = shadow_client.post(
        "/v1/shadow/ingest",
        json={"prompt": "Driver SSN 123-45-6789"},
        headers={"Authorization": "Bearer any-token"},
    )
    assert resp.status_code == 503


def test_shadow_ingest_rejects_invalid_or_missing_bearer_token(
    monkeypatch: pytest.MonkeyPatch, shadow_client: TestClient
) -> None:
    monkeypatch.setenv("LTA_TENANT_KEYS", json.dumps({"pilot_acme": "secret-token-123"}))

    r_missing = shadow_client.post("/v1/shadow/ingest", json={"prompt": "hello"})
    assert r_missing.status_code in (401, 403)

    r_wrong = shadow_client.post(
        "/v1/shadow/ingest",
        json={"prompt": "hello"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r_wrong.status_code in (401, 403)


def test_shadow_ingest_accepts_202_and_omits_raw_prompt_from_response(
    monkeypatch: pytest.MonkeyPatch, shadow_client: TestClient
) -> None:
    monkeypatch.setenv("LTA_TENANT_KEYS", json.dumps({"pilot_acme": "secret-token-123"}))
    raw_prompt = "Confidential dispatch SSN 123-45-6789 \u202e secret"

    resp = shadow_client.post(
        "/v1/shadow/ingest",
        json={"prompt": raw_prompt, "metadata": {"route": "I-94"}},
        headers={"Authorization": "Bearer secret-token-123"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert raw_prompt not in json.dumps(body)
    assert "123-45-6789" not in json.dumps(body)


def test_shadow_ingest_enforces_metadata_bounds(
    monkeypatch: pytest.MonkeyPatch, shadow_client: TestClient
) -> None:
    monkeypatch.setenv("LTA_TENANT_KEYS", json.dumps({"pilot_acme": "secret-token-123"}))
    oversized_meta = {f"k_{i}": "v" for i in range(25)}

    resp = shadow_client.post(
        "/v1/shadow/ingest",
        json={"prompt": "test", "metadata": oversized_meta},
        headers={"Authorization": "Bearer secret-token-123"},
    )
    assert resp.status_code in (400, 422)