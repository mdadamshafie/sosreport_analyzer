# SOSreport Analyzer V7 – Streamlit App
# Multi-stage build for smaller final image

# ── Stage 1: build dependencies ──────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ─────────────────────────────────────────
FROM python:3.11-slim

# System-level packages needed at runtime (none today, placeholder)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built Python packages from builder
COPY --from=builder /install /usr/local

# App directory
WORKDIR /app

# Bust Docker cache when app code changes (set automatically by compose)
ARG CACHEBUST=1

# Copy application code
COPY streamlit_app_v7.local.py ./streamlit_app.py
COPY .streamlit/ ./.streamlit/

# Streamlit config – headless, dark theme, CORS-friendly
ENV STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_ENABLE_CORS=true \
    STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=false

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "streamlit_app.py", \
            "--server.port=8501", \
            "--server.address=0.0.0.0"]
