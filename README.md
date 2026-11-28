```md
# Lucid-Truth-Audit

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED.svg)](Dockerfile)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF.svg)](.github/workflows/ci.yml)

**Lucid-Truth-Audit** is a deterministic security and compliance microservice for inspecting AI prompts, redacting sensitive data, recording tamper-evident audit evidence, and applying fleet logistics guardrails.

- **Repository:** https://github.com/stickneycorey1-source/Lucid-Truth-Audit-
- **Docker entry point:** `lta.app:app`
- **Health check:** `/healthz`
- **Interactive API documentation:** `/docs`

## Highlights

- Prompt injection, role spoofing, and anomalous-input detection
- PII and secret redaction for SSNs, payment cards, API keys, and other sensitive values
- Unicode normalization and homoglyph, Base64, Hex, URL, and invisible-character inspection
- Tamper-evident audit ledgers and tenant-isolated evidence chains
- Hash-only shadow ingestion for low-retention telemetry
- FMCSA-oriented hours-of-service, vehicle weight, permit, and waypoint guardrails
- Formula-injection-safe CSV audit exports
- API-key authentication, rate limiting, request-size limits, and defensive HTTP headers
- SQLite persistence with Docker and persistent Render disk support
- Automated unit, coverage, dependency, Docker, and live-endpoint validation

## Architecture

```text
HTTP request
    |
    v
Request size limit + security headers
    |
    v
Tenant/API-key authentication and rate limit
    |
    v
Unicode normalization and encoded-payload inspection
    |
    v
Policy, PII, and logistics guard evaluation
    |
    v
Redaction and allow/block decision
    |
    v
SQLite audit ledger / evidence chain
```

The application includes both compatibility modules and the Docker deployment package:

- `app/` contains the primary guard, ledger, evidence, normalizer, security, and logistics modules.
- `lta/` contains the Docker and Render application package.
- `policy_packs/` contains configurable policy definitions.
- `static/` contains the web portal assets.
- `tests/` and root-level `test_*.py` files contain unit and integration coverage.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Web portal |
| `GET` | `/health` | Application health summary |
| `GET` | `/healthz` | Container health probe |
| `GET` | `/docs` | Swagger UI |
| `POST` | `/api/v1/guard` | Prompt inspection and PII redaction |
| `POST` | `/api/v1/guard/logistics` | Logistics, HOS, weight, permit, and waypoint guard |
| `POST` | `/v1/shadow/ingest` | Hash-only shadow telemetry ingestion |
| `POST` | `/api/v1/evidence` | Append tenant evidence |
| `GET` | `/api/v1/evidence` | List tenant evidence |
| `GET` | `/api/v1/evidence/verify` | Verify the tenant evidence chain |
| `GET` | `/api/v1/audit/ledger` | Read tenant audit events |
| `GET` | `/api/v1/audit/export.csv` | Download a sanitized CSV audit export |

## Authentication

Protected endpoints require a configured API key. Authentication is fail-closed when required key configuration is missing or malformed.

```text
X-API-Key: <your-api-key>
```

Shadow ingestion uses a bearer token:

```text
Authorization: Bearer <your-shadow-key>
```

Never commit API keys, shadow keys, tenant mappings, or persistent database credentials.

## Core Guard Example

```bash
curl -X POST "http://localhost:10000/api/v1/guard" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-api-key>" \
  -d '{"prompt":"Driver SSN 123-45-6789"}'
```

The response contains the sanitized prompt, detected redaction types, tenant ID, framework version, and ledger entry hash.

## Logistics Guard

The logistics guard supports dispatch and compliance review workflows. It can validate:

- Single-shift driving and duty limits
- Continuous driving and rest-break requirements
- Federal gross vehicle weight limits
- Oversize/overweight permit identifiers
- Waypoint structure and labels
- Indirect prompt injection in logistics notes
- PII redaction in bills of lading and dispatcher summaries

Logistics decisions must be reviewed against current law and operational requirements. This repository is a technical aid and does not replace qualified legal, safety, or compliance review.

## Evidence and Audit Integrity

The SQLite-backed ledger and evidence stores use canonical serialization and chained hashes to detect modification of recorded data.

Security properties include:

- Tenant-isolated evidence chains
- Duplicate evidence detection
- Canonical JSON serialization
- Hash-chain verification endpoints
- Serialized database writes
- Formula-injection-neutralized CSV exports
- Sanitized filenames and HTTP response headers
- Bounded body, metadata, and result sizes

Persistent storage is recommended for production deployments. Audit data must be backed up and access-controlled according to the deployment's retention and compliance policy.

## Local Development

### Prerequisites

- Python 3.11 or compatible supported Python version
- Docker, if running the containerized service
- A virtual environment is recommended

### Install and run with Python

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

export LTA_API_KEY="change-me"
export LTA_SHADOW_KEY="change-me"
export LTA_TENANTS_JSON='{"github-actions":"change-me"}'
export LTA_AUDIT_DB_URL="sqlite:////var/data/lta_audit_ledger.db"

uvicorn lta.app:app --host 0.0.0.0 --port 10000
```

Open:

- `http://localhost:10000/docs`
- `http://localhost:10000/healthz`

The Python command uses Linux-style environment variables. Use the appropriate syntax for your shell or platform.

## Docker

```bash
docker build -t lucid-truth-audit .

docker run --rm -p 10000:10000 \
  -e LTA_API_KEY="change-me" \
  -e LTA_SHADOW_KEY="change-me" \
  -e LTA_TENANTS_JSON='{"github-actions":"change-me"}' \
  -e LTA_AUDIT_DB_URL="sqlite:////var/data/lta_audit_ledger.db" \
  -v lucid-lta-data:/var/data \
  lucid-truth-audit
```

The container runs `lta.app:app` on port `10000`, uses a non-root user, and includes a Docker health check against `/healthz`.

## Docker Compose

```bash
docker compose up --build
```

Review `docker-compose.yml` for published ports and environment configuration before exposing the service outside a trusted network.

## Configuration

| Variable | Purpose |
|---|---|
| `LTA_API_KEY` | Primary API key |
| `LTA_SHADOW_KEY` | Shadow-ingest bearer key |
| `LTA_TENANTS_JSON` | Tenant/API-key mappings |
| `LTA_DEFAULT_PROVIDER` | Default mock or configured provider |
| `LTA_DEFAULT_TENANT` | Default tenant identifier |
| `LTA_DEFAULT_POLICY` | Default policy pack |
| `LTA_AUDIT_DB_URL` | Audit SQLite or configured database URL |
| `LTA_CORS_ORIGINS` | Comma-separated CORS allowlist |
| `LTA_RATE_LIMIT_RPM` | Per-tenant request rate limit |

Do not enable unrestricted CORS in production. Store secrets in the platform's secret manager.

## Testing

Run the primary test suite:

```bash
python -m pytest -o addopts="" -v \
  --ignore=test_lta_gaps.py \
  --cov=app --cov=lta \
  --cov-report=term-missing
```

Run live-endpoint tests with appropriate credentials:

```bash
export LTA_BASE_URL="https://your-deployment.example.com"
export LTA_API_KEY="change-me"
export LTA_SHADOW_KEY="change-me"

python -m pytest -o addopts="" -v test_lta_gaps.py
```

The CI workflow also:

- Runs the dependency audit
- Enforces coverage minimums
- Builds the Docker image
- Generates HTML and JSON reports
- Runs live endpoint checks when repository secrets are available
- Uploads validation artifacts

CI configuration is in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Render Deployment

`render.yaml` defines a Docker web service for Render:

- Runtime: Docker
- Port: `10000`
- Health path: `/healthz`
- Persistent disk mounted at `/var/data`
- SQLite database at `sqlite:////var/data/lta_audit_ledger.db`
- Default policy: `general_enterprise`

Configure these secret values in Render rather than in source control:

- `LTA_TENANTS_JSON`
- `LTA_API_KEY`
- `LTA_SHADOW_KEY`

Before production use, verify persistent disk mounting, database backups, secret rotation, rate limits, CORS, and service scaling.

## Privacy and Retention

Shadow ingestion is designed around hash-only telemetry and should not be used to persist raw prompts by default. Retention behavior also depends on provider configuration, application logs, infrastructure, and database settings.

Operators should:

- Exclude raw prompt text from application logs
- Protect database and export access
- Define retention and deletion schedules
- Restrict tenant separation keys
- Encrypt backups and persistent volumes
- Perform security review before handling regulated data

## CSV Exports

Ledger exports sanitize spreadsheet formula prefixes and tenant-derived filenames. CSV output is intended to reduce spreadsheet formula-injection risk, but downloaded files should still be handled through normal security controls and not assumed to be cryptographically immutable.

## License

The source is licensed under the **Apache License 2.0**. Commercial enterprise licensing, private VPC deployment rights, custom regulatory policy packs, SLA guarantees, and shadow pilots are available separately under the notice included in [`LICENSE`](LICENSE).

Apache 2.0 does not guarantee security, fitness for compliance use, or absence of defects. Review and test all integrations before production deployment.
```