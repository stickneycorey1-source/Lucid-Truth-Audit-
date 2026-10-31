from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Lucid Truth Audit API")

class AuditRequest(BaseModel):
    # Pydantic explicitly restricts input length to block overflow attacks
    model_input: str = Field(..., max_length=1000, description="The AI prompt to evaluate")
    
class AuditResponse(BaseModel):
    status: str
    risk_level: str
    flagged_terms: list[str] = []

# Core Red Team Blocklist
RESTRICTED_TERMS = ["ignore previous instructions", "system prompt", "bypass", "jailbreak"]

@app.get("/")
def read_root():
    return {"message": "Lucid Truth Audit Engine is live."}

@app.post("/api/v1/guard", response_model=AuditResponse)
def run_guardrail(req: AuditRequest):
    input_text = req.model_input.lower()
    
    # Scan for hostile prompt injection
    flagged = [term for term in RESTRICTED_TERMS if term in input_text]
    
    if flagged:
        return AuditResponse(
            status="blocked", 
            risk_level="critical", 
            flagged_terms=flagged
        )
        
    return AuditResponse(status="clean", risk_level="low")
