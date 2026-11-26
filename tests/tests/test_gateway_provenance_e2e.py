"""End-to-end gateway tests for policy-version tracking, config fingerprints, and provenance."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterator, Tuple

import pytest
from fastapi.testclient import TestClient

from lta.app import create_app
from lta.config import Settings


@pytest.fixture()
def pilot_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Tuple[TestClient, Path]]:
    db_file = tmp_path / "p2_provenance_e2e.db"
    monkeypatch.setenv("LTA_DEFAULT_PROVIDER", "mock")
    monkeypatch.setenv("LTA_AUDIT_DB_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("LTA_SHADOW_KEY", "shadow-p2-pilot-token-2026")
    monkeypatch.setenv(
        "LTA_TENANTS_JSON",
        json.dumps(
            [
                {
                    "tenant_id": "p2_transport_pilot",
                    "api_key": "p2-client-key-2026",
                    "policy_pack": "general_enterprise",
                    "provider": "mock",
                    "rate_limit_rpm": 120,
                    "role": "client",
                },
                {
                    "tenant_id": "lucid_secops_admin",
                    "api_key": "lta-admin-key-2026",
                    "policy_pack": "general_enterprise",
                    "provider": "mock",
                    "rate_limit_rpm": 300,
                    "role": "admin",
                },
            ]
        ),
    )
    app = create_app(Settings.from_env())
    with TestClient(app) as client:
        yield client, db_file


def test_chat_and_shadow_emit_verifiable_provenance_and_detect_config_tampering(
    pilot_client: Tuple[TestClient, Path],
) -> None:
    client, db_file = pilot_client

    chat_resp = client.post(
        "/v1/chat/completions",
        headers={"X-API-Key": "p2-client-key-2026"},
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": "Summarize standard fleet dispatch status for load PO8492014.",
                }
            ],
        },
    )
    assert chat_resp.status_code == 200, f"Unexpected {chat_resp.status_code}: {chat_resp.text}"
    body = chat_resp.json()
    audit_meta = body["lta_audit"]
    assert audit_meta["policy_pack"] == "general_enterprise"
    assert len(audit_meta["policy_sha256"]) == 64
    assert len(audit_meta["config_fingerprint"]) == 64
    assert len(audit_meta["provenance_hash"]) == 64
    assert len(audit_meta["entry_hash"]) == 64

    shadow_resp = client.post(
        "/v1/shadow/ingest",
        headers={"Authorization": "Bearer shadow-p2-pilot-token-2026"},
        json={
            "prompt": "Shadow check for driver manifest PO8492014",
            "request_id": "p2-shadow-nov30",
        },
    )
    assert shadow_resp.status_code == 202
    shadow_body = shadow_resp.json()
    assert shadow_body["zero_retention"] is True
    assert isinstance(shadow_body["audit_id"], str) and len(shadow_body["audit_id"]) > 0
    assert len(shadow_body["entry_hash"]) == 64
    assert len(shadow_body["policy_sha256"]) == 64
    assert len(shadow_body["config_fingerprint"]) == 64
    assert len(shadow_body["provenance_hash"]) == 64

    verify_ok = client.get(
        "/v1/audit/verify",
        headers={"X-API-Key": "lta-admin-key-2026"},
    )
    assert verify_ok.status_code == 200
    verify_data = verify_ok.json()
    assert verify_data["chain_valid"] is True
    assert verify_data["total_entries"] == 2
    assert verify_data["first_broken_seq_id"] is None

    export_resp = client.get(
        "/v1/audit/export",
        headers={"X-API-Key": "lta-admin-key-2026"},
    )
    assert export_resp.status_code == 200
    exported_rows = [json.loads(line) for line in export_resp.text.strip().splitlines()]
    assert len(exported_rows) == 2
    for row in exported_rows:
        assert "policy_version" in row
        assert len(row["policy_sha256"]) == 64
        assert len(row["config_fingerprint"]) == 64
        assert len(row["provenance_hash"]) == 64

    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute("UPDATE audit_events SET policy_version = '0.0.1-forged' WHERE seq_id = 1")
        conn.commit()
    finally:
        conn.close()

    verify_broken = client.get(
        "/v1/audit/verify",
        headers={"X-API-Key": "lta-admin-key-2026"},
    )
    assert verify_broken.status_code == 200
    broken_data = verify_broken.json()
    assert broken_data["chain_valid"] is False
    assert broken_data["first_broken_seq_id"] == 1