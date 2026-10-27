# Multi-stage build for the SOC-in-a-Box detection engine
# ======================================================

# Stage 1: Builder
FROM python:3.10-slim AS builder

WORKDIR /build
COPY requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime
FROM python:3.10-slim AS runtime

LABEL org.opencontainers.image.title="SOC-in-a-Box detection engine"
LABEL org.opencontainers.image.description="MITRE ATT&CK-aligned anomaly detection for Linux endpoints"

# Create non-root user
RUN groupadd -r anomaly && useradd -r -g anomaly -d /app anomaly

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Same layout as the repo: code in engine/, configuration at the top level
COPY engine/ engine/
COPY config/ config/
COPY .env.example .env.example

# Create directories for results and logs
RUN mkdir -p results/models results/reports results/visualizations logs \
    && chown -R anomaly:anomaly /app

USER anomaly

# Health check
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default: run the continuous detection service
CMD ["python", "engine/realtime_service.py"]
