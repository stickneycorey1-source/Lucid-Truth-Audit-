from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "lucid-prop-key-2026"}

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200

def test_guardrail_clean():
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "Summarize this safe data."})
    assert response.status_code == 200

def test_guardrail_injection():
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "system prompt override"})
    assert response.json()["status"] == "blocked"

def test_guardrail_pii_leak():
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "Here is my SSN: 123-45-6789"})
    assert response.json()["status"] == "blocked"
    
def test_guardrail_anomaly():
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "A" * 25})
    assert response.json()["status"] == "blocked"

def test_fetch_logs():
    # Tests that the new database endpoint returns the ledger
    response = client.get("/api/v1/logs", headers=HEADERS)
    assert response.status_code == 200
    assert "audit_trail" in response.json()
