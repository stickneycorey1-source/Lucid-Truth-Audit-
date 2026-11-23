from app.ledger import audit_ledger
from app.evidence_chain import EvidenceChainStore, DuplicateEvidenceError
from app.schemas.logistics_guard import router as logistics_router

logger = logging.getLogger("lucid_truth_audit")

FRAMEWORK_VERSION = "2.0.3"

app = FastAPI(
    title="Lucid-Truth-Audit",
    version=FRAMEWORK_VERSION,
    description="Production Deterministic AI Security, PII Redaction, Evidence Chain, and FMCSA Fleet Compliance Engine",
)