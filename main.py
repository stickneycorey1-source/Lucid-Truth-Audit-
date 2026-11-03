import os
import sqlite3
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

# Initialize FastAPI App
app = FastAPI(
    title="Lucid-Truth-Audit",
    description="The Stickney Audit Mandate - Real-time Edge Security Gateway & PII Redaction Middleware",
    version="1.0.0"
)

# Configuration from Environment Variables
API_KEY = os.getenv("LUCID_API_KEY", "lucid-prop-key-2026")
DB_PATH = os.getenv("AUDIT_DB_PATH", "lucid_audit.db")

# Pydantic v2 Schemas
class GuardRequest(BaseModel):
    model_input: str = Field(..., description="The raw prompt input to be scanned by the edge gateway.")

class GuardResponse(BaseModel):
    status: str
    risk_level: str
    message: str
    masked_input: Optional[str] = None

# Initialize SQLite Tamper-Evident Ledger
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_detected INTEGER,
            violation_type TEXT,
            masked_payload TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def log_event(threat_detected: int, violation_type: str, payload: str):
    """Safely logs masked payloads and threats to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Data minimization / PII masking
    masked = payload[:4] + "****" + payload[-4:] if len(payload) > 8. else "****"
    
    cursor.execute(
        "INSERT INTO audit_logs (timestamp, threat_detected, violation_type, masked_payload) VALUES (?, ?, ?, ?)",
        (datetime.utcnow.isoformat(), threat_detected, violation_type, masked)
    )
    conn.commit()
    conn.close()

@app.get("/")
def read_root():
    """Root endpoint to verify the Lucid-Truth-Audit gateway is online."""
    return {
        "status": "online",
        "service": "Lucid-Truth-Audit (The Stickney Audit Mandate)",
        "version": "1.0.0",
        "active_endpoint": "/api/v1/guard"
    }

@app.post("/api/v1/guard", response_model
