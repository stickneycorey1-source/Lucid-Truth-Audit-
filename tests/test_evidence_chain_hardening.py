"""Unit tests covering per-tenant evidence hash chain in app/evidence_chain.py."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.evidence_chain import DuplicateEvidenceError, EvidenceChainStore


@pytest.fixture
def chain_store(tmp_path: Path) -> EvidenceChainStore:
    return EvidenceChainStore(str(tmp_path / "evidence_chain_hardening.db"))


def test_evidence_append_list_and_verify_per_tenant(chain_store: EvidenceChainStore) -> None:
    rec1 = chain_store.add(
        tenant_id="tenant_a",
        evidence_id="EV-001",
        payload={"type": "hos_audit", "driver": "driver_1", "drive_hours": 7.5},
    )
    rec2 = chain_store.add(
        tenant_id="tenant_b",
        evidence_id="EV-001",
        payload={"type": "hos_audit", "driver": "driver_2", "drive_hours": 6.0},
    )
    assert rec1["entry_hash"] != rec2["entry_hash"]
    assert rec1["prev_hash"] == "GENESIS"
    assert rec2["prev_hash"] == "GENESIS"

    rows_a = chain_store.list_records(tenant_id="tenant_a", limit=10)
    assert len(rows_a) == 1
    assert rows_a[0]["evidence_id"] == "EV-001"

    res_a = chain_store.verify(tenant_id="tenant_a")
    res_b = chain_store.verify(tenant_id="tenant_b")
    assert res_a == {"chain_valid": True, "checked_records": 1, "broken_at_record": None}
    assert res_b == {"chain_valid": True, "checked_records": 1, "broken_at_record": None}


def test_evidence_duplicate_id_raises_conflict_error(chain_store: EvidenceChainStore) -> None:
    chain_store.add(
        tenant_id="tenant_a",
        evidence_id="EV-DUP-1",
        payload={"type": "pii_audit", "redacted": ["SSN"]},
    )
    with pytest.raises(DuplicateEvidenceError):
        chain_store.add(
            tenant_id="tenant_a",
            evidence_id="EV-DUP-1",
            payload={"type": "pii_audit", "redacted": ["SSN"]},
        )


@pytest.mark.parametrize("bad_val", [float("nan"), float("inf"), float("-inf")])
def test_evidence_rejects_non_finite_payload_numbers(
    chain_store: EvidenceChainStore, bad_val: float
) -> None:
    with pytest.raises(ValueError):
        chain_store.add(
            tenant_id="tenant_a",
            evidence_id="EV-NAN",
            payload={"type": "weight_check", "weight_lbs": bad_val},
        )


def test_evidence_rejects_blank_tenant_id(chain_store: EvidenceChainStore) -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        chain_store.add(tenant_id="   ", payload={"ok": True})


def test_evidence_detects_tampering_and_supports_concurrent_writes(
    chain_store: EvidenceChainStore, tmp_path: Path
) -> None:
    db_path = tmp_path / "evidence_chain_hardening.db"

    def _worker(idx: int) -> None:
        chain_store.add(
            tenant_id="tenant_conc",
            evidence_id=f"EV-CONC-{idx:03d}",
            payload={"type": "telemetry", "seq": idx},
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(_worker, range(15)))

    res_before = chain_store.verify(tenant_id="tenant_conc")
    assert res_before["chain_valid"] is True
    assert res_before["checked_records"] == 15

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "UPDATE evidence_records SET entry_hash = ? WHERE tenant_id = ? AND id = 1",
            ("f" * 64, "tenant_conc"),
        )
        conn.commit()
    finally:
        conn.close()

    res_after = chain_store.verify(tenant_id="tenant_conc")
    assert res_after["chain_valid"] is False
    assert res_after["broken_at_record"] == 1