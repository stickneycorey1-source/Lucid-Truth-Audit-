import sqlite3
import json
from datetime import datetime

DB_NAME = "lucid_audit_ledger.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            model_input TEXT,
            status TEXT,
            flagged_data TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_audit(model_input: str, status: str, flagged_data: list):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (timestamp, model_input, status, flagged_data) VALUES (?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), model_input, status, json.dumps(flagged_data))
    )
    conn.commit()
    conn.close()

def get_logs(limit: int = 20):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, model_input, status, flagged_data FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{"timestamp": r[0], "prompt": r[1], "status": r[2], "flags": json.loads(r[3])} for r in rows]
    
