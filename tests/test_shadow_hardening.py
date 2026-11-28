"""Unit tests covering hardening changes in app/api/shadow.py."""

from __future__ import annotations

import hashlib
import json
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api.shadow as shadow_mod
from app.api.shadow import (
    MAX_METADATA_KEY_LEN,
    MAX_METADATA_KEYS,
    MAX_METADATA_VAL_LEN,
    ShadowIngestRequest,
    ZeroRetentionAuditRecord,
    _process_shadow_payload,
    router as shadow_router,
)


def _make_client() -> TestClient:
    mini_app = FastAPI()
    mini_app.include_router(shadow_router)
    return TestClient(mini_app)


@pytest.fixture(autouse=True)
def _clean_shadow_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LTA_TENANT_KEYS", raising=False)


# ---------------------------------------------------------------------------
# 1. Fail-closed 503 on missing or malformed LTA_TENANT_KEYS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "env_val",
    [
        None,
        "",
        "{not-valid-json",
        json.dumps(["not", "a", "dict"]),
        json.dumps({"   ": "key", "tenant": "   "}),
    ],
)
def test_shadow_ingest_returns_503_when_unconfigured_or_malformed(
    monkeypatch: pytest.MonkeyPatch, env_val: str | None
) -> None:
    if env_val is not None:
        monkeypatch.setenv("LTA_TENANT_KEYS", env_val)

    client = _make_client()
    resp = client.post(
        "/v1/shadow/ingest",
        json={"prompt": "hello"},
        headers={"Authorization": "Bearer any-key"},
    )
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 2. 401 on missing/malformed/empty/invalid Bearer tokens & case-insensitive scheme
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "auth_header",
    [
        None,
        "Basic dXNlcjpwYXNz",
        "Bearer ",
        "Bearer    ",
        "Bearer wrong-key",
    ],
)
def test_shadow_ingest_returns_401_on_invalid_auth(
    monkeypatch: pytest.MonkeyPatch, auth_header: str | None
) -> None:
    monkeypatch.setenv("LTA_TENANT_KEYS", json.dumps({"pilot_acme": "valid-shadow-key"}))
    client = _make_client()

    headers = {"Authorization": auth_header} if auth_header is not None else {}
    resp = client.post("/v1/shadow/ingest", json={"prompt": "hello"}, headers=headers)
    assert resp.status_code == 401


def test_shadow_ingest_accepts_case_insensitive_bearer_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LTA_TENANT_KEYS", json.dumps({"pilot_acme": "valid-shadow-key"}))
    emitted: list[ZeroRetentionAuditRecord] = []
    monkeypatch.setattr(shadow_mod, "write_audit_record", emitted.append)

    client = _make_client()
    resp = client.post(
        "/v1/shadow/ingest",
        json={"prompt": "hello world"},
        headers={"Authorization": "bearer valid-shadow-key"},
    )
    assert resp.status_code == 202
    assert resp.json()["tenant_id"] == "pilot_acme"
    assert len(emitted) == 1


# ---------------------------------------------------------------------------
# 3. Metadata bounds validation (422)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_metadata",
    [
        {f"k{i}": "v" for i in range(MAX_METADATA_KEYS + 1)},
        {"   ": "v"},
        {"k" * (MAX_METADATA_KEY_LEN + 1): "v"},
        {"env": "v" * (MAX_METADATA_VAL_LEN + 1)},
    ],
)
def test_shadow_ingest_rejects_out_of_bounds_metadata(
    monkeypatch: pytest.MonkeyPatch, bad_metadata: dict[str, str]
) -> None:
    monkeypatch.setenv("LTA_TENANT_KEYS", json.dumps({"pilot_acme": "valid-shadow-key"}))
    client = _make_client()

    resp = client.post(
        "/v1/shadow/ingest",
        json={"prompt": "hello", "metadata": bad_metadata},
        headers={"Authorization": "Bearer valid-shadow-key"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 4. Zero-retention audit record emission (no raw/sanitized prompt leaked)
# ---------------------------------------------------------------------------


def test_shadow_ingest_emits_zero_retention_audit_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LTA_TENANT_KEYS", json.dumps({"pilot_acme": "valid-shadow-key"}))
    emitted: list[ZeroRetentionAuditRecord] = []
    monkeypatch.setattr(shadow_mod, "write_audit_record", emitted.append)

    secret_prompt = "SSN 123-45-6789 \u202e p\u0430ssword"
    client = _make_client()
    resp = client.post(
        "/v1/shadow/ingest",
        json={
            "prompt": secret_prompt,
            "request_id": "req-shadow-1",
            "model_target": "gpt-4o-mini",
            "metadata": {"env": "prod"},
        },
        headers={"Authorization": "Bearer valid-shadow-key"},
    )

    assert resp.status_code == 202
    body = resp.json()
    expected_sha = hashlib.sha256(secret_prompt.encode("utf-8")).hexdigest()
    assert body["input_sha256"] == expected_sha
    assert body["tenant_id"] == "pilot_acme"

    assert len(emitted) == 1
    record = emitted[0]
    dumped = record.model_dump_json()

    assert record.audit_id == body["audit_id"]
    assert record.input_sha256 == expected_sha
    assert record.bidi_override_detected is True
    assert "BIDI_OVERRIDE" in record.risk_flags
    # Zero-retention guarantee: neither raw PII nor prompt text appears in the serialized record
    assert "123-45-6789" not in dumped
    assert "password" not in dumped
    assert "p\u0430ssword" not in dumped


# ---------------------------------------------------------------------------
# 5. Background worker error containment (no raw prompt in error logs)
# ---------------------------------------------------------------------------


def test_background_worker_contains_exceptions_without_leaking_prompt(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _boom(_text: str):
        raise RuntimeError("synthetic sanitizer crash")

    monkeypatch.setattr(shadow_mod._sanitizer, "sanitize", _boom)

    payload = ShadowIngestRequest(prompt="TOP_SECRET_SSN_999-99-9999")
    with caplog.at_level(logging.ERROR, logger="lucid_truth_audit.shadow"):
        _process_shadow_payload(
            audit_id="aud_test_err",
            tenant_id="pilot_acme",
            input_sha256="a" * 64,
            payload=payload,
        )

    messages = [r.getMessage() for r in caplog.records]
    assert any(
        "shadow.worker_failed" in m
        and "audit_id=aud_test_err" in m
        and "tenant=pilot_acme" in m
        and "error_type=RuntimeError" in m
        for m in messages
    )
    assert all("TOP_SECRET_SSN_999-99-9999" not in m for m in messages)