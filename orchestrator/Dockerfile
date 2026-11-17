# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# soc-orchestrator: FastAPI + LangGraph, Python 3.11
# ---------------------------------------------------------------------------

# ---- build stage: compile wheels into an isolated venv ----------------------
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip && pip install -r /tmp/requirements.txt

# ---- runtime stage: no compilers, no pip cache, non-root --------------------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --system --gid 10001 soc \
 && useradd --system --uid 10001 --gid soc --no-create-home --shell /usr/sbin/nologin soc \
 && mkdir -p /var/lib/soc && chown 10001:10001 /var/lib/soc && chmod 700 /var/lib/soc

COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=root:root app/ ./app/

USER 10001:10001
EXPOSE 8000

# 0.0.0.0 here is the container's own interface. What the outside world can
# reach is decided by the host-side port binding in docker-compose.yml.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--no-server-header", "--log-level", "info"]
