import hashlib
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(
    title="Lucid-Truth-Audit",
    description="The Stickney Audit Mandate - Real-time Edge Security Gateway & PII Redaction Middleware",
    version="1.0.0",
)

# Fail closed if LUCID_API_KEY is unset in production
API_KEY = os.getenv("LUCID_API_KEY")
if not API_KEY:
    raise RuntimeError("LUCID_API_KEY environment variable must be set.")

DB_PATH = os.getenv("AUDIT_DB_PATH", "lucid_audit.db")


class GuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_input: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The raw prompt input to be scanned by the edge gateway.",
    )


class GuardResponse(BaseModel):
    status: str
    risk_level: str
    message: str
    masked_input: Optional[str] = None


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_detected INTEGER NOT NULL,
                violation_type TEXT NOT NULL,
                masked_payload TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            )
            """
        )


init_db()


def log_event(threat_detected: int, violation_type: str, payload: str) -> None:
    """Safely logs hashed and redacted payloads to the SQLite ledger."""
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    masked = f"[REDACTED len={len(payload)}]"
    timestamp = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (timestamp, threat_detected, violation_type, masked_payload, payload_sha256)
            VALUES (?, ?, ?, ?, ?)
            """,
            (timestamp, threat_detected, violation_type, masked, payload_hash),
        )
