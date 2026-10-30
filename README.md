# Lucid Truth Audit

An AI Red Team compliance engine and guardrail microservice, developed by Dr. Lucid. 

## Features
- **Proprietary Asset**: All rights reserved under commercial copyright.
- **FastAPI Guardrails**: Real-time evaluation endpoints for AI inputs.
- **Pydantic v2**: Strict domain schemas and data validation.
- **Automated Reporting**: Generates NIST/OWASP compliance audit logs.
- **CI/CD Integration**: Zero-tolerance automated testing pipelines.

## Quickstart
1. Install dependencies: `pip install -r requirements.txt`
2. Start the server: `uvicorn main:app --reload`
3. Run the automated audit: `python3 audit_scorer.py audit_log.json`
