import sqlite3
import os

DB_NAME = os.getenv("AUDIT_DB_PATH", "lucid_audit.db")

def init_db():
    """Initializes the SQLite audit ledger with a unified schema."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            endpoint TEXT,
            threat_detected BOOLEAN,
            violation_type TEXT,
            masked_payload TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_audit_event(client_ip: str, endpoint: str, threat_detected: bool, violation_type: str, payload: str):
    """Logs an audit event with PII masking."""
    # Mask potential SSNs or sensitive strings before writing to SQLite
    masked = payload
    if len(payload) > 10:
        masked = payload[:4] + "****" + payload[-4:]

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (client_ip, endpoint, threat_detected, violation_type, masked_payload)
        VALUES (?, ?, ?, ?, ?)
    """, (client_ip, endpoint, threat_detected, violation_type, masked))
    conn.commit()
    conn.close()
