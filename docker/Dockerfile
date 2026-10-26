# Multi-stage build for Linux Anomaly Detection
# ================================================

# Stage 1: Builder
FROM python:3.10-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY requirements*.txt ./

RUN pip install --no-cache-dir --prefix=/install -e "." 2>/dev/null || \
    pip install --no-cache-dir --prefix=/install \
        "elasticsearch>=8.0.0,<9" \
        "scikit-learn>=1.3.0" \
        "numpy>=1.24.0" \
        "pandas>=1.5.0" \
        "scipy>=1.9.0" \
        "pyod>=1.1.0" \
        "joblib>=1.3.0" \
        "requests>=2.28.0" \
        "pyyaml>=6.0" \
        "python-dotenv>=1.0.0" \
        "matplotlib>=3.5.0" \
        "seaborn>=0.12.0"

# Stage 2: Runtime
FROM python:3.10-slim AS runtime

LABEL maintainer="Linux Anomaly Detection Contributors"
LABEL description="MITRE ATT&CK-aligned anomaly detection for Linux endpoints"

# Create non-root user
RUN groupadd -r anomaly && useradd -r -g anomaly -d /app anomaly

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY *.py ./
COPY config/ config/
COPY features/ features/
COPY models/ models/
COPY dl_models/ dl_models/
COPY backends/ backends/
COPY adversarial/ adversarial/
COPY benign_lists.py .
COPY .env.example .env.example

# Create directories for results and logs
RUN mkdir -p results/models results/reports results/visualizations logs \
    && chown -R anomaly:anomaly /app

USER anomaly

# Health check
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default: run the continuous detection service
CMD ["python", "realtime_service.py"]
