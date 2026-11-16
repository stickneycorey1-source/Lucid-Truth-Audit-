import os
import sqlite3
import psycopg

DATABASE_URL = os.getenv("DATABASE_URL")
DB_PATH = os.getenv("AUDIT_DB_PATH", "lucid_audit.db")


def get_connection():
    if DATABASE_URL:
        return psycopg.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    id_col = "SERIAL PRIMARY KEY" if DATABASE_URL else "INTEGER PRIMARY KEY AUTOINCREMENT"
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id {id_col},
                timestamp TEXT NOT NULL,
                threat_detected INTEGER NOT NULL,
                violation_type TEXT NOT NULL,
                masked_payload TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            )
            """
        )
        conn.commit()


def insert_audit_log(
    timestamp: str,
    threat_detected: int,
    violation_type: str,
    masked_payload: str,
    payload_sha256: str,
) -> None:
    ph = "%s" if DATABASE_URL else "?"
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"""
            INSERT INTO audit_logs (timestamp, threat_detected, violation_type, masked_payload, payload_sha256)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph})
            """,
            (timestamp, threat_detected, violation_type, masked_payload, payload_sha256),
        )
        conn.commit()
