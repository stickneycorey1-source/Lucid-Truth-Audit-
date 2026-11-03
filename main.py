import os
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from database import init_db, log_audit_event

app = FastAPI(title="Lucid-Truth-Audit Gateway", version="1.0.0")

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_db()

class PromptPayload(BaseModel):
    prompt: str = Field(..., description="The user prompt or query destined for the LLM pipeline.")
    jurisdiction: str = Field(default="US", description="Target compliance jurisdiction (e.g., US, EU).")

def verify_api_key(x_api_key: str = Header(...)):
    """Enforces strict API key authentication from environment variables."""
    expected_key = os.getenv("LUCID_API_KEY")
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: LUCID_API_KEY environment variable is not set."
        )
    if x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing x-api-key header."
        )
    return x_api_key

@app.post("/audit", status_code=status.HTTP_200_OK)
async def audit_prompt(request: Request, payload: PromptPayload, x_api_key: str = Header(...)):
    verify_api_key(x_api_key)
    
    client_ip = request.client.host if request.client else "unknown"
    prompt_text = payload.prompt.lower()

    # Heuristic threat and PII detection matrix
    threat_detected = False
    violation_type = "None"

    if "ignore previous instructions" in prompt_text or "system prompt" in prompt_text:
        threat_detected = True
        violation_type = "Prompt Injection"
    elif "ssn" in prompt_text or "social security" in prompt_text:
        threat_detected = True
        violation_type = "PII Exfiltration (SSN)"

    # Log to the persistent SQLite ledger
    log_audit_event(
        client_ip=client_ip,
        endpoint="/audit",
        threat_detected=threat_detected,
        violation_type=violation_type,
        payload=payload.prompt
    )

    if threat_detected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Payload intercepted by Lucid-Truth-Audit edge guardrail.",
                "violation": violation_type,
                "status": "Blocked",
                "tokens_burned": 0
            }
        )

    return {
        "status": "Approved",
        "jurisdiction": payload.jurisdiction,
        "message": "Payload passed Pydantic v2 edge validation."
    }
