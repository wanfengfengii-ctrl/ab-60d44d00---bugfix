# Forensic PKI adjudication service — reproducible image.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

# System health-check client (curl) only; no build toolchain needed because
# cryptography ships manylinux wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY app /srv/app
COPY verify /srv/verify
COPY tests /srv/tests
COPY acceptance /srv/acceptance

ENV DATA_DIR=/data \
    API_HOST=0.0.0.0 \
    API_PORT=8080

EXPOSE 8080

# Persistent data volume mount point.
RUN mkdir -p /data
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD curl -fsS "http://127.0.0.1:${API_PORT}/healthz" || exit 1

CMD ["python", "-m", "app.main"]
