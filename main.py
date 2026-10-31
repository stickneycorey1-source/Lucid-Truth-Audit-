import re
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

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

# Core Red Team Blocklist
RESTRICTED_TERMS = ["ignore previous instructions", "system prompt", "bypass", "jailbreak", "sudo"]

# Regex Patterns for Data Leaks
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
    
    # 1. Jailbreak & Prompt Injection Scan
    flagged_terms = [term for term in RESTRICTED_TERMS if term in input_text]
    
    # 2. PII / Data Leak Scan (Uses original case)
    flagged_pii = []
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, req.model_input):
            flagged_pii.append(pii_type)
            
    # 3. Anomaly / Buffer Overflow Scan (Blocks 20+ repeating characters)
    if re.search(r"(.)\1{20,}", input_text):
        flagged_terms.append("anomaly_repeating_chars")

    if flagged_terms or flagged_pii:
        return AuditResponse(
            status="blocked", 
            risk_level="critical", 
            flagged_terms=flagged_terms,
            flagged_pii=flagged_pii
        )
        
    return AuditResponse(status="clean", risk_level="low")
