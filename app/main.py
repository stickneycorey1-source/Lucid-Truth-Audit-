--- a/app/main.py
+++ b/app/main.py
@@ -20,11 +20,14 @@ from app.ledger import audit_ledger
 from app.evidence_chain import EvidenceChainStore, DuplicateEvidenceError
 from app.schemas.logistics_guard import router as logistics_router
 
 logger = logging.getLogger("lucid_truth_audit")
 
+FRAMEWORK_VERSION = "2.0.3"
+
 app = FastAPI(
     title="Lucid-Truth-Audit",
-    version="2.0.2",
+    version=FRAMEWORK_VERSION,
     description="Production Deterministic AI Security, PII Redaction, Evidence Chain, and FMCSA Fleet Compliance Engine",
 )
 
 # Configurable CORS allowlist for external portals (e.g., Vercel React frontend)
@@ -180,7 +183,7 @@ class GuardResponse(BaseModel):
     tenant_id: str
     sanitized_prompt: str
     sanitized_messages: Optional[List[MessageTurn]] = None
     redacted_entities: List[str]
-    framework_version: str = "2.0.2"
+    framework_version: str = FRAMEWORK_VERSION
     ledger_entry_hash: str
 
 
@@ -220,7 +223,7 @@ async def health_check():
     stats = audit_ledger.get_summary_stats()
     return {
         "status": "healthy",
         "framework": "Lucid-Truth-Audit",
-        "version": "2.0.2",
+        "version": FRAMEWORK_VERSION,
         "ledger_records": stats["ledger_records"],
         "latest_hash_prefix": stats["latest_hash_prefix"],
         "vectors": ["vector1_injection", "vector2_pii", "vector3_resilience", "vector4_logistics"],