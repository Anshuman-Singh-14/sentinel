# syntax=docker/dockerfile:1
# Multi-stage build (04-security.md section 10):
#   deps-*  resolve the locked virtualenv with uv (build tooling never ships)
#   dev     app + dev tools (pytest, ruff, mypy, bandit), used by docker compose
#   runtime app only, used by the production profile
# Every runtime stage runs as an unprivileged user (UID 10001).

ARG PYTHON_IMAGE=python:3.12-slim

FROM ghcr.io/astral-sh/uv:0.12.21 AS uv

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid sentinel --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin sentinel
WORKDIR /app

FROM base AS deps-base
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./

FROM deps-base AS deps-prod
RUN uv sync --frozen --no-dev --no-install-project

FROM deps-base AS deps-dev
RUN uv sync --frozen --no-install-project

FROM base AS dev
COPY --from=deps-dev /opt/venv /opt/venv
COPY --chown=sentinel:sentinel . .
# Tool caches go to /tmp: the source tree may be a read-only or host bind mount.
ENV RUFF_CACHE_DIR=/tmp/ruff-cache \
    MYPY_CACHE_DIR=/tmp/mypy-cache \
    XDG_CACHE_HOME=/tmp/.cache
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers", "--log-config", "uvicorn-logging.json"]

FROM base AS runtime
COPY --from=deps-prod /opt/venv /opt/venv
COPY --chown=root:root app ./app
COPY --chown=root:root alembic ./alembic
COPY --chown=root:root alembic.ini uvicorn-logging.json ./
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers", "--log-config", "uvicorn-logging.json"]
