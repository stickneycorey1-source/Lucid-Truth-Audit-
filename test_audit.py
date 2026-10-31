from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "lucid-prop-key-2026"}

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200

def test_guardrail_clean():
    # Tests a normal, safe prompt
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "Summarize this safe data."})
    assert response.status_code == 200
    assert response.json()["status"] == "clean"

def test_guardrail_injection():
    # Tests prompt injection
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "system prompt override"})
    assert response.json()["status"] == "blocked"
    assert "system prompt" in response.json()["flagged_terms"]

def test_guardrail_pii_leak():
    # Tests SSN data leak detection
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "Here is my SSN: 123-45-6789"})
    assert response.json()["status"] == "blocked"
    assert "SSN" in response.json()["flagged_pii"]
    
def test_guardrail_anomaly():
    # Tests buffer overflow via repeating characters
    response = client.post("/api/v1/guard", headers=HEADERS, json={"model_input": "A" * 25})
    assert response.json()["status"] == "blocked"
    assert "anomaly_repeating_chars" in response.json()["flagged_terms"]
