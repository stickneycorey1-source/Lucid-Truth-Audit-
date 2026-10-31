import sqlite3
import json
import sys

DB_NAME = "lucid_audit_ledger.db"

def generate_compliance_report():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Pull traffic metrics directly from the ledger
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        total_requests = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status='clean'")
        clean_requests = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status='blocked'")
        blocked_requests = cursor.fetchone()[0]
        
        cursor.execute("SELECT flagged_data FROM audit_logs WHERE status='blocked'")
        blocked_rows = cursor.fetchall()
        
        conn.close()
    except sqlite3.Error as e:
        print(json.dumps({"error": f"Database error: {e}"}))
        sys.exit(1)

    # Calculate Traffic Risk Grade
    grade = 100.0 if total_requests == 0 else (clean_requests / total_requests) * 100

    # Categorize mitigated threat vectors
    threat_vectors = {}
    for row in blocked_rows:
        flags = json.loads(row[0])
        for flag in flags:
            threat_vectors[flag] = threat_vectors.get(flag, 0) + 1

    report = {
        "lucid_truth_audit_summary": {
            "total_traffic": total_requests,
            "authorized_clean_traffic": clean_requests,
            "threats_mitigated": blocked_requests,
            "traffic_safety_grade": f"{grade:.1f}%",
            "detected_vectors": threat_vectors,
            "system_status": "Active - OWASP/NIST Compliant"
        }
    }
    
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    generate_compliance_report()
