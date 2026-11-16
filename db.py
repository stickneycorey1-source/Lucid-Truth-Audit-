import os
import sqlite3
import uuid
from datetime import datetime, timezone
import psycopg

DATABASE_URL = os.getenv("DATABASE_URL")
AUDIT_DB_PATH = os.getenv("AUDIT_DB_PATH", "lucid_audit.db")


def get_db_connection():
    if DATABASE_URL:
        return psycopg.connect(DATABASE_URL)
    return sqlite3.connect(AUDIT_DB_PATH)


def init_audit_table():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                detected_vector TEXT
            )
            """
        )
        conn.commit()


def log_audit_event(payload_sha256: str, status: str, detected_vector: str | None = None) -> str:
    audit_id = str(uuid.uuid4())
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    ph = "%s" if DATABASE_URL else "?"

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"""
            INSERT INTO audit_logs (id, timestamp_utc, payload_sha256, status, detected_vector)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph})
            """,
            (audit_id, timestamp_utc, payload_sha256, status, detected_vector),
        )
        conn.commit()
    return audit_id
