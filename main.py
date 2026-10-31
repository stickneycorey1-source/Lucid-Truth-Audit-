import re
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field
from database import init_db, log_audit

# Spin up the SQLite database on launch
init_db()

app = FastAPI(title="Lucid Truth Audit API")

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)
MASTER_KEY = "lucid-prop-key-2026"

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != MASTER_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return api_key

class AuditRequest(BaseModel):
    model_input: str = Field(..., max_length=1000)
    
class AuditResponse(BaseModel):
    status: str
    risk_level: str
    flagged_terms: list[str] = []
    flagged_pii: list[str] = []

RESTRICTED_TERMS = ["ignore previous instructions", "system prompt", "bypass", "jailbreak", "sudo"]

PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Email": r"[\w\.-]+@[\w\.-]+\.\w+",
    "Credit_Card": r"\b(?:\d[ -]*?){13,16}\b"
}

@app.get("/")
def read_root():
    return {"message": "Lucid Truth Audit Engine is live."}

@app.post("/api/v1/guard", response_model=AuditResponse)
def run_guardrail(req: AuditRequest, api_key: str = Depends(verify_api_key)):
    input_text = req.model_input.lower()
    
    flagged_terms = [term for term in RESTRICTED_TERMS if term in input_text]
    flagged_pii = [pii for pii, pattern in PII_PATTERNS.items() if re.search(pattern, req.model_input)]
    
    if re.search(r"(.)\1{20,}", input_text):
        flagged_terms.append("anomaly_repeating_chars")

    flagged_all = flagged_terms + flagged_pii

    # Write the outcome to the secure database ledger
    if flagged_all:
        log_audit(req.model_input, "blocked", flagged_all)
        return AuditResponse(
            status="blocked", 
            risk_level="critical", 
            flagged_terms=flagged_terms,
            flagged_pii=flagged_pii
        )
        
    log_audit(req.model_input, "clean", [])
    return AuditResponse(status="clean", risk_level="low")
    
