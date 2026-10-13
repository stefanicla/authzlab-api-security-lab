# AuthZLab Dockerfile
# Multi-stage build for minimal production image

# Build stage
FROM python:3.14-slim AS builder

WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

# Copy project metadata AND sources before install (C-1a: uv sync builds
# the project, so it needs src/ and README.md present).
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

# Install dependencies (project included; single runtime env, see C-1b/c)
RUN uv sync --frozen --no-dev

# Runtime stage
FROM python:3.14-slim AS runtime

WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy the builder venv plus the sources the editable install points at (C-1b)
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src

# Set PATH to use venv
ENV PATH="/app/.venv/bin:$PATH"
# H-2: container default must bind all interfaces so published ports work;
# local-dev console scripts still default to 127.0.0.1 via cli.py.
ENV HOST="0.0.0.0"

# Switch to non-root user
USER appuser

# Health check (raise_for_status so /health/ready 503 marks unhealthy)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://127.0.0.1:8000/health/ready', timeout=3).raise_for_status()"

# Expose port
EXPOSE 8000

# Default command (secure app)
CMD ["authzlab-secure"]
