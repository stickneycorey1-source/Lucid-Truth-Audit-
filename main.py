from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

app = FastAPI(title="Lucid Truth Audit API")

# Setup API Key Security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)
MASTER_KEY = "lucid-prop-key-2026"

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != MASTER_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized: Invalid API Key")
    return api_key

class AuditRequest(BaseModel):
    model_input: str = Field(..., max_length=1000)
    
class AuditResponse(BaseModel):
    status: str
    risk_level: str
    flagged_terms: list[str] = []

RESTRICTED_TERMS = ["ignore previous instructions", "system prompt", "bypass", "jailbreak"]

@app.get("/")
def read_root():
    return {"message": "Lucid Truth Audit Engine is live."}

# The Depends(verify_api_key) locks this endpoint down
@app.post("/api/v1/guard", response_model=AuditResponse)
def run_guardrail(req: AuditRequest, api_key: str = Depends(verify_api_key)):
    input_text = req.model_input.lower()
    flagged = [term for term in RESTRICTED_TERMS if term in input_text]
    
    if flagged:
        return AuditResponse(status="blocked", risk_level="critical", flagged_terms=flagged)
        
    return AuditResponse(status="clean", risk_level="low")
