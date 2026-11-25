Latency Benchmarks Summary:
Gateway / Auth / Ledger / Shadow Fast Path (Checks 1–4, 7–9): 68.7 ms min (#2 /readyz), 102.8 ms max (#4 /v1/shadow/ingest), 93.8 ms on BiDi + Homoglyph shadow ingest (#9), and 71.7 ms on audit ledger verification (#8).
Upstream LLM Guard Path (Checks 5–6): 1883.9 ms (PII + secret redaction turn) and 4269.4 ms (clean prompt turn).
License
Commercial / Proprietary License — All Rights Reserved.
Copyright (c) 2026 Corey Allen Stickney / Lucid Truth Audit.
This software, documentation, test suites, policy engines, and compliance artifacts are proprietary and confidential. No license is granted to copy, modify, distribute, sublicense, sell, or deploy this software in production, staging, or commercial environments except under a written commercial agreement or authorized 30-day evaluation pilot executed with the rights holder.