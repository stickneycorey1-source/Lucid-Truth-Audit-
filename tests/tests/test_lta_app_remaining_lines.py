"""Unit tests covering remaining uncovered helpers, pipeline paths, and endpoints in lta/app.py."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

import lta.app as lta_app_mod
from lta.audit_ledger import AuditRecord
from lta.config import Settings, TenantConfig
from lta.providers import ProviderResponse, UpstreamProviderError


def _make_settings(
    db_file: Path,
    tenants: Optional[List[Dict[str, Any]]] = None,
    *,
    default_provider: str = "mock",
) -> Settings:
    cfg = Settings(
        audit_db_url=f"sqlite:///{db_file}",
        redis_url=None,
        default_provider=default_provider,
    )
    loaded: Dict[str, TenantConfig] = {}
    for entry in tenants or []:
        key_hash = hashlib.sha256(entry["api_key"].encode("utf-8")).hexdigest()
        loaded[key_hash] = TenantConfig(
            tenant_id=entry["tenant_id"],
            key_hash=key_hash,
            policy_pack=entry.get("policy_pack", "general_enterprise"),
            provider=entry.get("provider", default_provider),
            upstream_model=entry.get("upstream_model", "gpt-4o-mini"),
            rate_limit_rpm=entry.get("rate_limit_rpm", 200),
            role=entry.get("role", "client"),
        )
    cfg.tenants = loaded
    return cfg


def test_helper_client_ip_jsonl_hash_and_sqlite_inspection(tmp_path: Path) -> None:
    req_no_client = SimpleNamespace(headers={}, client=None)
    assert lta_app_mod._client_ip(req_no_client) == "unknown"  # type: ignore[arg-type]

    assert lta_app_mod._format_jsonl_rows(None) == ""
    assert lta_app_mod._format_jsonl_rows('{"a":1}') == '{"a":1}\n'
    formatted = lta_app_mod._format_jsonl_rows(['{"x":1}', {"y": 2}, ""])
    lines = formatted.strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1]) == {"y": 2}

    rec = AuditRecord(
        seq_id=1,
        timestamp="2026-11-26T00:00:00Z",
        tenant_id="t1",
        endpoint="/v1/chat/completions",
        policy_pack="general_enterprise",
        provider="mock",
        action="ALLOW",
        http_status=200,
        vector=None,
        redactions=[],
        payload_sha256="a" * 64,
        prev_hash="0" * 64,
        entry_hash="b" * 64,
    )
    assert lta_app_mod._extract_entry_hash(rec, "seed") == "b" * 64
    assert lta_app_mod._extract_entry_hash({"entry_hash": "c" * 64}, "seed") == "c" * 64
    assert lta_app_mod._extract_entry_hash(SimpleNamespace(event_hash="d" * 64), "seed") == "d" * 64
    fallback_hash = lta_app_mod._extract_entry_hash(object(), "deterministic-seed")
    assert len(fallback_hash) == 64

    assert lta_app_mod._resolve_sqlite_path(None) is None
    assert lta_app_mod._resolve_sqlite_path("sqlite:///:memory:") is None

    db_file = tmp_path / "chain_inspect.db"
    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute(
            "CREATE TABLE audit_events (seq_id INTEGER PRIMARY KEY, prev_hash TEXT, entry_hash TEXT)"
        )
        conn.execute(
            "INSERT INTO audit_events (seq_id, prev_hash, entry_hash) VALUES (?, ?, ?)",
            (1, "bad_prev_hash", "f" * 64),
        )
        conn.commit()
    finally:
        conn.close()

    assert lta_app_mod._resolve_sqlite_path(f"sqlite:///{db_file}") == str(db_file)
    broken, broken_seq = lta_app_mod._inspect_sqlite_chain(f"sqlite:///{db_file}")
    assert broken is True
    assert broken_seq == 1


def test_unpack_verify_result_and_disable_docs_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert lta_app_mod._unpack_verify_result((True, 5, None)) == (True, 5, None)
    assert lta_app_mod._unpack_verify_result(
        {"chain_valid": False, "total_entries": 3, "first_broken_seq_id": 2}
    ) == (False, 3, 2)
    assert lta_app_mod._unpack_verify_result(True) == (True, None, None)

    monkeypatch.setenv("LTA_DISABLE_DOCS", "true")
    cfg = _make_settings(
        tmp_path / "docs_disabled.db",
        [{"tenant_id": "t1", "api_key": "k1", "role": "client"}],
    )
    app = lta_app_mod.create_app(cfg)
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_auth_rejection_and_tenant_rate_limit_headers(tmp_path: Path) -> None:
    cfg = _make_settings(
        tmp_path / "rate_limit.db",
        [
            {
                "tenant_id": "throttled_tenant",
                "api_key": "throttled-key",
                "role": "client",
                "rate_limit_rpm": 2,
            }
        ],
    )
    app = lta_app_mod.create_app(cfg)
    with TestClient(app) as client:
        r_bad = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "wrong-key"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r_bad.status_code in (401, 403)

        statuses = [
            client.post(
                "/v1/chat/completions",
                headers={"X-API-Key": "throttled-key"},
                json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "ping"}]},
            ).status_code
            for _ in range(4)
        ]
        assert 200 in statuses
        assert 429 in statuses


def test_pipeline_redaction_output_guard_and_upstream_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _make_settings(
        tmp_path / "pipeline.db",
        [{"tenant_id": "ops_client", "api_key": "ops-key", "role": "client"}],
    )
    app = lta_app_mod.create_app(cfg)
    raw_ssn = "123-45-6789"

    with TestClient(app) as client:
        r_redact = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "ops-key"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"Driver SSN {raw_ssn} dispatch"}],
            },
        )
        assert r_redact.status_code in (200, 400, 422)
        assert raw_ssn not in r_redact.text

    async def _leaking_reply(**kwargs: Any) -> ProviderResponse:
        return ProviderResponse(
            content=f"Leaked SSN {raw_ssn} and sk-live-secret-1234567890abcdef",
            model=kwargs.get("model", "gpt-4o-mini"),
            provider="mock",
        )

    monkeypatch.setattr(lta_app_mod, "call_upstream", _leaking_reply)
    with TestClient(app) as client:
        r_leak = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "ops-key"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Run report"}]},
        )
        assert r_leak.status_code in (200, 400, 403, 422, 502)
        assert raw_ssn not in r_leak.text

    async def _boom_reply(**kwargs: Any) -> ProviderResponse:
        raise UpstreamProviderError("upstream down")

    monkeypatch.setattr(lta_app_mod, "call_upstream", _boom_reply)
    with TestClient(app) as client:
        r_err = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "ops-key"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Run report"}]},
        )
        assert r_err.status_code in (500, 502, 503)


def test_audit_export_verify_and_metrics_endpoints(tmp_path: Path) -> None:
    cfg = _make_settings(
        tmp_path / "export_verify.db",
        [
            {"tenant_id": "fleet_one", "api_key": "fleet-one-key", "role": "client"},
            {"tenant_id": "admin_user", "api_key": "admin-key", "role": "admin"},
        ],
    )
    app = lta_app_mod.create_app(cfg)

    with TestClient(app) as client:
        r_chat = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "fleet-one-key"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Load OK"}]},
        )
        assert r_chat.status_code == 200

        r_export = client.get(
            "/v1/audit/export",
            params={"tenant_id": "fleet_one"},
            headers={"X-API-Key": "admin-key"},
        )
        assert r_export.status_code == 200
        rows = [json.loads(line) for line in r_export.text.splitlines() if line.strip()]
        assert len(rows) >= 1
        assert all(row.get("tenant_id") == "fleet_one" for row in rows)

        r_verify = client.get("/v1/audit/verify", headers={"X-API-Key": "admin-key"})
        assert r_verify.status_code == 200
        assert r_verify.json().get("chain_valid") is True

        r_metrics = client.get("/metrics", headers={"X-API-Key": "admin-key"})
        assert r_metrics.status_code == 200
        assert len(r_metrics.text.strip()) > 0