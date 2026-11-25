"""Unit tests for AuditLedger tamper detection, filtering, ping failures, and provider helpers."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from lta.audit_ledger import AuditLedger
from lta.providers import UpstreamProviderError, _scrub_secrets, validate_upstream_url


def _seed_two_records(ledger: AuditLedger) -> None:
    ledger.record(
        tenant_id="tenant-alpha",
        endpoint="/api/v1/guard",
        policy_pack="general_enterprise",
        provider="mock",
        action="ALLOW",
        http_status=200,
        vector=None,
        redactions=[],
        raw_payload_for_digest="first clean prompt",
        latency_ms=12.3456,
    )
    ledger.record(
        tenant_id="tenant-beta",
        endpoint="/v1/chat/completions",
        policy_pack="healthcare_hipaa",
        provider="mock",
        action="ALLOW_REDACTED",
        http_status=200,
        vector=None,
        redactions=["SSN"],
        raw_payload_for_digest="second prompt with redacted ssn",
        latency_ms=25.6789,
    )


def test_ledger_verify_chain_valid_and_detects_tampering(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.db"
    db_url = f"sqlite:///{db_path}"
    ledger = AuditLedger(db_url)
    try:
        _seed_two_records(ledger)
        valid, total, broken_seq = ledger.verify_chain()
        assert valid is True
        assert total == 2
        assert broken_seq is None

        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "UPDATE audit_events SET action = ? WHERE seq_id = ?",
                ("BLOCK", 1),
            )
            conn.commit()
        finally:
            conn.close()

        valid_after, total_after, broken_after = ledger.verify_chain()
        assert valid_after is False
        assert total_after == 2
        assert broken_after == 1
    finally:
        ledger.close()


def test_ledger_export_jsonl_filters_by_tenant_id(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path / 'export.db'}"
    ledger = AuditLedger(db_url)
    try:
        _seed_two_records(ledger)
        exported = ledger.export_jsonl(tenant_id="tenant-beta", limit=10)
        lines = [json.loads(line) for line in exported.splitlines() if line.strip()]
        assert len(lines) == 1
        assert lines[0]["tenant_id"] == "tenant-beta"
        assert lines[0]["redactions"] == ["SSN"]
    finally:
        ledger.close()


def test_ledger_ping_returns_false_on_connection_error(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path / 'ping.db'}"
    ledger = AuditLedger(db_url)
    try:
        with patch.object(ledger, "_connection", side_effect=RuntimeError("db down")):
            assert ledger.ping() is False
    finally:
        ledger.close()


def test_validate_upstream_url_enforces_https_and_local_hosts() -> None:
    assert (
        validate_upstream_url("https://api.openai.com/v1/")
        == "https://api.openai.com/v1"
    )
    assert (
        validate_upstream_url("http://localhost:11434/v1/")
        == "http://localhost:11434/v1"
    )
    with pytest.raises(UpstreamProviderError):
        validate_upstream_url("http://api.openai.com/v1")


def test_scrub_secrets_redacts_common_tokens() -> None:
    raw = (
        "tokens: sk-1234567890abcdef1234 "
        "ghp_1234567890abcdefghijklmnopqrstuv "
        "AKIA1234567890ABCDEF "
        "AIzaSyDummyKey123456789012345678901"
    )
    scrubbed = _scrub_secrets(raw)
    assert "sk-1234567890abcdef1234" not in scrubbed
    assert "ghp_1234567890abcdefghijklmnopqrstuv" not in scrubbed
    assert "AKIA1234567890ABCDEF" not in scrubbed
    assert "AIzaSyDummyKey123456789012345678901" not in scrubbed
    assert scrubbed.count("[REDACTED_SECRET]") >= 4