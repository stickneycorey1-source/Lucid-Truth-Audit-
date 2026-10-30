from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Lucid Truth Audit Engine is live."}

def test_guardrail_endpoint():
    response = client.post("/api/v1/guard", json={"model_input": "Test dataset"})
    assert response.status_code == 200
    assert response.json()["status"] == "clean"
