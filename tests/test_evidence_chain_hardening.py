"""Unit tests covering per-tenant evidence hash chain in app/evidence_chain.py."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import app.evidence_chain as ev_mod


@pytest.fixture
def chain_store(tmp_path: Path) -> ev_mod.EvidenceChainStore:
    return ev_mod.EvidenceChainStore(str(tmp_path / "evidence_chain_hardening.db"))


def test_evidence_append_list_and_verify_per_tenant(chain_store: ev_mod.EvidenceChainStore) -> None:
    rec1 = chain_store.append_evidence(
        tenant_id="tenant_a",
        evidence_id="EV-001",
        evidence_type="hos_audit",
        payload={"driver": "driver_1", "drive_hours": 7.5},
    )
    rec2 = chain_store.append_evidence(
        tenant_id="tenant_b",
        evidence_id="EV-001",
        evidence_type="hos_audit",
        payload={"driver": "driver_2", "drive_hours": 6.0},
    )
    assert rec1["entry_hash"] != rec2["entry_hash"]

    rows_a = chain_store.list_evidence(tenant_id="tenant_a", limit=10)
    assert len(rows_a) == 1
    assert rows_a[0]["evidence_id"] == "EV-001"

    ok_a, msg_a = chain_store.verify_chain(tenant_id="tenant_a")
    ok_b, msg_b = chain_store.verify_chain(tenant_id="tenant_b")
    assert ok_a is True, msg_a
    assert ok_b is True, msg_b


def test_evidence_duplicate_id_raises_conflict_error(chain_store: ev_mod.EvidenceChainStore) -> None:
    chain_store.append_evidence(
        tenant_id="tenant_a",
        evidence_id="EV-DUP-1",
        evidence_type="pii_audit",
        payload={"redacted": ["SSN"]},
    )
    with pytest.raises(ev_mod.DuplicateEvidenceError):
        chain_store.append_evidence(
            tenant_id="tenant_a",
            evidence_id="EV-DUP-1",
            evidence_type="pii_audit",
            payload={"redacted": ["SSN"]},
        )


@pytest.mark.parametrize("bad_val", [float("nan"), float("inf"), float("-inf")])
def test_evidence_rejects_non_finite_payload_numbers(
    chain_store: ev_mod.EvidenceChainStore, bad_val: float
) -> None:
    with pytest.raises((ValueError, TypeError)):
        chain_store.append_evidence(
            tenant_id="tenant_a",
            evidence_id="EV-NAN",
            evidence_type="weight_check",
            payload={"weight_lbs": bad_val},
        )


def test_evidence_detects_tampering_and_supports_concurrent_writes(
    chain_store: ev_mod.EvidenceChainStore, tmp_path: Path
) -> None:
    db_path = tmp_path / "evidence_chain_hardening.db"

    def _worker(idx: int) -> None:
        chain_store.append_evidence(
            tenant_id="tenant_conc",
            evidence_id=f"EV-CONC-{idx:03d}",
            evidence_type="telemetry",
            payload={"seq": idx},
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(_worker, range(15)))

    ok_before, _ = chain_store.verify_chain(tenant_id="tenant_conc")
    assert ok_before is True

    conn = sqlite3.connect(str(db_path))
    try:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(evidence_records)").fetchall()]
        if "entry_hash" in cols:
            conn.execute(
                "UPDATE evidence_records SET entry_hash = ? WHERE tenant_id = ?",
                ("f" * 64, "tenant_conc"),
            )
            conn.commit()
    finally:
        conn.close()

    ok_after, _ = chain_store.verify_chain(tenant_id="tenant_conc")
    assert ok_after is False