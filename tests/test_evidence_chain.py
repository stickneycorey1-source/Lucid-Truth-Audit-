Python

import hashlib
import os
import sqlite3

from fastapi.testclient import TestClient

from app.main import app
from app.ledger import audit_ledger
from app.security import rate_limiter


client = TestClient(app)
HEADERS = {"X-API-Key": "evidence-test-key"}


def payload():
    return {
        "claim": "The source supports the stated claim.",
        "source_uri": "https://example.org/source",
        "source_sha256": hashlib.sha256(
            b"example source"
        ).hexdigest(),
        "evidence_summary": "A source passage relevant to the claim.",
        "evidence_type": "document",
        "rule_id": "CLAIM-SUPPORT",
        "rule_version": "1.0.0",
        "test_results": [
            {"test": "source_match", "passed": True}
        ],
        "counterexamples": [
            {
                "description": "Alternative interpretation",
                "resolved": False,
            }
        ],
    }


def setup_function():
    os.environ["LUCID_TENANT_KEYS"] = (
        "evidence_tenant:evidence-test-key:never,"
        "other_tenant:other-test-key:never"
    )
    rate_limiter.reset()


def test_create_and_verify_evidence(tmp_path):
    audit_ledger.reconfigure(str(tmp_path / "evidence.db"))

    response = client.post(
        "/api/v1/evidence",
        json=payload(),
        headers=HEADERS,
    )

    assert response.status_code == 201
    assert response.json()["entry_hash"]

    verified = client.get(
        "/api/v1/evidence/verify",
        headers=HEADERS,
    )

    assert verified.status_code == 200
    assert verified.json()["chain_valid"] is True
    assert verified.json()["checked_records"] == 1


def test_caller_supplied_source_hash_is_not_marked_verified(tmp_path):
    audit_ledger.reconfigure(str(tmp_path / "provenance.db"))

    response = client.post(
        "/api/v1/evidence",
        json=payload(),
        headers=HEADERS,
    )

    assert response.status_code == 201

    provenance = response.json()["payload"]["source_hash_provenance"]

    assert provenance["algorithm"] == "SHA-256"
    assert provenance["origin"] == "caller_supplied"
    assert provenance["status"] == "unverified"
    assert provenance["verified"] is False
    assert provenance["verification_method"] is None


def test_evidence_is_tenant_isolated(tmp_path):
    audit_ledger.reconfigure(str(tmp_path / "tenant.db"))

    created = client.post(
        "/api/v1/evidence",
        json=payload(),
        headers=HEADERS,
    )

    assert created.status_code == 201

    other = client.get(
        "/api/v1/evidence",
        headers={"X-API-Key": "other-test-key"},
    )

    assert other.status_code == 200
    assert other.json()["records"] == []


def test_evidence_survives_store_recreation(tmp_path):
    from app.evidence_chain import EvidenceChainStore

    db = str(tmp_path / "persistent.db")
    store = EvidenceChainStore(db)
    store.add("tenant_a", payload())

    reopened = EvidenceChainStore(db)

    assert len(reopened.list_records("tenant_a")) == 1
    assert reopened.verify("tenant_a")["chain_valid"] is True


def test_tampered_evidence_is_detected(tmp_path):
    from app.evidence_chain import EvidenceChainStore

    db = str(tmp_path / "tamper.db")
    store = EvidenceChainStore(db)
    store.add("tenant_a", payload())

    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            UPDATE evidence_records
            SET payload_json = ?
            WHERE tenant_id = ?
            """,
            ('{"claim":"altered"}', "tenant_a"),
        )

    result = store.verify("tenant_a")

    assert result["chain_valid"] is False
