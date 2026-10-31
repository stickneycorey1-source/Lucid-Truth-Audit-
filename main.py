from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
import sqlite3
from datetime import datetime
import re

# --- 1. Database Setup & Logging ---
def init_audit_ledger():
    conn = sqlite3.connect('lucid_audit.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            risk_level TEXT,
            raw_input TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Fire immediately on Render server boot
init_audit_ledger()

def log_threat(risk_level: str, raw_input: str):
    conn = sqlite3.connect('lucid_audit.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO blocked_threats (timestamp, risk_level, raw_input) VALUES (?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), risk_level, raw_input)
    )
    conn.commit()
    conn.close()


# --- 2. FastAPI App & Security ---
app = FastAPI(title="Stickney-Audit-Mandate API")

# Match this to your frontend Colab script
API_KEY = "lucid-prop-key-2026"
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key


# --- 3. Pydantic v2 Schemas ---
class GuardRequest(BaseModel):
    model_input: str = Field(..., description="The raw user input to be audited")

class GuardResponse(BaseModel):
    status: str
    risk_level: str = "none"
    message: str = "cleared"


# --- 4. Guardrail Logic & Endpoint ---
@app.post("/api/v1/guard", response_model=GuardResponse)
async def guard_endpoint(request: GuardRequest, api_key: str = Depends(verify_api_key)):
    user_text = request.model_input.lower()
    
    # Heuristics for threat detection (Injection keywords & PII patterns)
    is_injection = "ignore all previous instructions" in user_text or "system prompt" in user_text
    is_pii = "ssn" in user_text or re.search(r"\d{3}-\d{2}-\d{4}", user_text)
    
    # Intercept and Block
    if is_injection or is_pii:
        # Write the attack to the SQLite ledger
        log_threat(risk_level="critical", raw_input=request.model_input)
        
        # Return the exact JSON structure your frontend expects
        return GuardResponse(
            status="blocked",
            risk_level="critical",
            message="Security protocols engaged. Threat logged."
        )

    # Clear safe inputs
    return GuardResponse(status="cleared", risk_level="none", message="Input safe.")
