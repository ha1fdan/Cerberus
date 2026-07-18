# --- Build Stage ---
FROM ghcr.io/astral-sh/uv:python3.14-alpine AS builder

# Production optimization: Pre-compiles .py files to .pyc bytecode for instant container cold starts
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /app

# Copy the configuration files first to optimize Docker layer caching
COPY pyproject.toml uv.lock* ./

# Install project dependencies without installing the code project itself yet
RUN uv sync --no-install-project --no-dev

# Copy the actual application source code
COPY ./app /app/app

# Sync the entire project to build out the environment
RUN uv sync --no-dev

# --- Final Production Stage ---
FROM python:3.14-alpine
WORKDIR /app

# Copy the pre-built, self-contained virtual environment from the builder
COPY --from=builder /app/.venv /app/.venv

# Copy the application code
COPY ./app /app/app

# Place the virtual environment path at the front of the system PATH
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 5000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]