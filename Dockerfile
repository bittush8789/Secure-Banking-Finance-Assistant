# ==============================================================================
# Multi-Stage Secure Dockerfile for Secure Banking & Finance Assistant POC
# ==============================================================================

# --- Stage 1: Build Dependencies ---
FROM python:3.11-slim AS builder

WORKDIR /install

# Install build dependencies required for compiling C extensions (if any)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install pinned wheels into isolated prefix directory
RUN pip install --no-cache-dir --prefix=/install/package -r requirements.txt


# --- Stage 2: Final Minimal Runtime Image ---
FROM python:3.11-slim AS runner

# Create non-root system group and user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# Install only minimal runtime shared libraries (libpq for PostgreSQL driver)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 \
        curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed Python packages from builder stage
COPY --from=builder /install/package /usr/local

# Copy application source code and approved procedure documents
COPY app/ /app/app/
COPY data/ /app/data/

# Secure ownership: set all files as readable by non-root user
RUN chown -R appuser:appgroup /app && \
    chmod -R 755 /app

# Switch permanently to non-root user
USER appuser

# Expose internal container port
EXPOSE 8000

# Container liveness check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Launch production ASGI server via Uvicorn
ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
