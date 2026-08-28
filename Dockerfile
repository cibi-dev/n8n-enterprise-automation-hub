# ==============================================================================
# Enterprise Multi-Stage Dockerfile for n8n Enterprise Automation Hub Runner
# Conforms to DevSecOps Standards: Non-root user, minimal attack surface, multi-stage
# ==============================================================================

# Build Stage
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# Production Stage
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="n8n-enterprise-automation-hub" \
      org.opencontainers.image.description="Enterprise n8n Workflow Automation Hub & Multi-Domain Pipeline Orchestrator" \
      org.opencontainers.image.authors="cibi-dev" \
      org.opencontainers.image.vendor="Automation & SRE Engineering" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app:/app/packages/n8n-devsecops-audit-bridge/src:/app/packages/n8n-osint-threat-feed-enricher/src:/app/packages/n8n-forensic-incident-triage/src:/app/packages/n8n-sre-resilience-sentinel/src:/app/packages/n8n-rag-knowledge-sync-hub/src"

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Create non-root user for DevSecOps compliance
RUN groupadd -r automation && useradd -r -g automation -u 1001 -m -d /app n8n_operator

# Copy application code and workflows
COPY --chown=n8n_operator:automation cli.py pyproject.toml README.md ./
COPY --chown=n8n_operator:automation packages/ ./packages/
COPY --chown=n8n_operator:automation workflows/ ./workflows/

USER n8n_operator

ENTRYPOINT ["python3", "/app/cli.py"]
CMD ["demo"]
