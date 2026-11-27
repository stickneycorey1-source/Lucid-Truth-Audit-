"""Targeted unit tests covering branches in lta/app.py using persistent SQLite paths."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

import lta.app as lta_app_mod
from lta.config import Settings, TenantConfig


def _build_test_settings(
    db_file: Path,
    *,
    tenants: Optional[List[Dict[str, Any]]] = None,
    default_provider: str = "mock",
) -> Settings:
    cfg = Settings(
        audit_db_url=f"sqlite:///{db_file}",
        redis_url=None,
        default_provider=default_provider,
    )
    if tenants is None:
        cfg.tenants = {}
        return cfg

    loaded: Dict[str, TenantConfig] = {}
    for t in tenants:
        key_hash = hashlib.sha256(t["api_key"].encode("utf-8")).hexdigest()
        loaded[key_hash] = TenantConfig(
            tenant_id=t["tenant_id"],
            key_hash=key_hash,
            policy_pack=t.get("policy_pack", "general_enterprise"),
            provider=t.get("provider", default_provider),
            upstream_model=t.get("upstream_model", "gpt-4o-mini"),
            rate_limit_rpm=t.get("rate_limit_rpm", 100),
            role=t.get("role", "client"),
        )
    cfg.tenants = loaded
    return cfg


def test_unconfigured_tenants_and_auth_rate_limit(tmp_path: Path) -> None:
    empty_app = lta_app_mod.create_app(_build_test_settings(tmp_path / "empty.db", tenants=[]))
    with TestClient(empty_app, raise_server_exceptions=False) as client:
        r_empty = client.get("/v1/policies", headers={"X-API-Key": "any-key"})
        assert r_empty.status_code == 500

    cfg = _build_test_settings(
        tmp_path / "auth_limit.db",
        tenants=[{"tenant_id": "client_1", "api_key": "valid-client-key", "role": "client"}],
    )
    app = lta_app_mod.create_app(cfg)
    with TestClient(app) as client:
        statuses = [
            client.get("/v1/policies", headers={"X-API-Key": "bad-key"}).status_code
            for _ in range(25)
        ]
        assert 403 in statuses
        assert 429 in statuses

        r_admin_check = client.get("/v1/audit/verify", headers={"X-API-Key": "valid-client-key"})
        assert r_admin_check.status_code == 403


def test_non_admin_policy_override_blocked_and_snapshot_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _build_test_settings(
        tmp_path / "snapshot_fallback.db",
        tenants=[{"tenant_id": "fleet_client", "api_key": "client-key-123", "role": "client"}],
    )
    app = lta_app_mod.create_app(cfg)

    def _boom_snapshot(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("snapshot write failed")

    with TestClient(app) as client:
        r_override = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "client-key-123", "X-LTA-Policy": "fmcsa"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]},
        )
        assert r_override.status_code == 403
        assert r_override.json()["detail"]["vector"] == "security.unauthorized_policy_override"

        monkeypatch.setattr(app.state.audit_ledger, "record_snapshot", _boom_snapshot, raising=False)
        r_ok = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "client-key-123"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Dispatch check"}]},
        )
        assert r_ok.status_code == 200


def test_middleware_invalid_content_length_and_shadow_tenant_auth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("LTA_SHADOW_KEY", raising=False)
    monkeypatch.setattr(lta_app_mod, "MAX_BODY_BYTES", 256)

    cfg = _build_test_settings(
        tmp_path / "middleware_shadow.db",
        tenants=[{"tenant_id": "shadow_tenant", "api_key": "tenant-shadow-key", "role": "client"}],
    )
    app = lta_app_mod.create_app(cfg)

    with TestClient(app) as client:
        r_bad_cl = client.get(
            "/healthz",
            headers={"Content-Length": "not-an-int", "X-Request-ID": "req-cl-test"},
        )
        assert r_bad_cl.status_code == 200
        assert r_bad_cl.headers["X-Request-ID"] == "req-cl-test"

        r_shadow_ok = client.post(
            "/v1/shadow/ingest",
            headers={"Authorization": "Bearer tenant-shadow-key"},
            json={"prompt": "Shadow telemetry probe"},
        )
        assert r_shadow_ok.status_code == 202
        assert r_shadow_ok.json()["accepted"] is True

        r_shadow_bad = client.post(
            "/v1/shadow/ingest",
            headers={"Authorization": "Bearer wrong-shadow-key"},
            json={"prompt": "Shadow telemetry probe"},
        )
        assert r_shadow_bad.status_code == 403

        r_large_body = client.post(
            "/v1/shadow/ingest",
            headers={"Authorization": "Bearer tenant-shadow-key"},
            content=json.dumps({"prompt": "x" * 400}),
        )
        assert r_large_body.status_code == 413


def test_lifespan_handles_ledger_close_exception(tmp_path: Path) -> None:
    cfg = _build_test_settings(
        tmp_path / "lifespan_close.db",
        tenants=[{"tenant_id": "t1", "api_key": "k1", "role": "client"}],
    )
    app = lta_app_mod.create_app(cfg)

    def _close_raises() -> None:
        raise OSError("close failed")

    app.state.audit_ledger.close = _close_raises  # type: ignore[method-assign]
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200