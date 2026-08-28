# Security Policy — `n8n-enterprise-automation-hub`

## Standards Applied (SECURITY.md Canonical #1–17)

### Base Controls (#1–5)
- **#1 Secrets:** Zero credentials in repository or workflow JSON exports. Webhook secrets injected via environment variables only.
- **#2 Webhook Input Validation:** All incoming payloads validated via Pydantic v2 models with `extra='forbid'` before ingestion.
- **#3 Output Sanitization:** Notifications, Telegram digests, and Obsidian notes stripped of raw PII (CWE-209).
- **#4 Lockfiles & Pinning:** Dependencies pinned in `pyproject.toml` and verified via CycloneDX SBOM.
- **#5 Structured Security Logging:** Webhook processing logs structured with execution IDs, zero auth tokens logged.

### Phase 2 Controls (#6–13)
- **#7 Payload Size Bounding:** Webhook endpoints enforce 1MB maximum payload limits to mitigate buffer exhaustion (CWE-400).
- **#8 State Persistence:** SQLite cache and audit bridge store records with parameterized statements and WAL mode.
- **#9 Cryptographic Verification:** Webhook payloads signed and verified using HMAC-SHA256 constant-time comparison (`hmac.compare_digest()`).
- **#10 Exponential Backoff:** Threat feed ingestor and notification exporters implement retry budgets with jitter.
- **#11 Immutability:** Audit bridge records security events into Merkle-anchored SQLite storage.
- **#12 Blue-Green Auto-Rollback:** SRE sentinel triggers automated sub-millisecond atomic rollback on probe degradation ($<0.05\text{ ms}$).
- **#13 Deduplication Accuracy:** MinHash LSH deduplication ($K=64$) prevents alert floods without dropping critical CVEs.

### AI & Integration Controls (#14–17)
- **#14 Anti-SSRF:** All external feed URLs (CISA, NVD) and outbound webhooks validated against denylist (127.0.0.1, 10.0.0.0/8, 169.254.169.254) (CWE-918).
- **#15 AST Codebase Chunking:** RAG knowledge sync hub parses Python source code via AST nodes, avoiding unsafe regex chunking.
- **#16 Human-in-the-Loop:** SRE automated rollbacks generate incident tickets and require operator postmortem sign-off.
- **#17 Ingestion Rate Limiting:** Feed fetchers enforce rate limits and SQLite caching to prevent remote API throttling.

## Reporting Vulnerabilities
Open a private security advisory via GitHub Security Advisories or contact `cibi-dev@users.noreply.github.com`.
