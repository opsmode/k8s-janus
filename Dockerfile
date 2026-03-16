FROM python:3.12-alpine

ARG BUILD_DATE=unknown
ARG APP_VERSION=dev
ENV BUILD_DATE=${BUILD_DATE}
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app

# Upgrade all packages to pick up security patches, then install build deps
RUN apk upgrade --no-cache && \
    apk add --no-cache libpq gcc musl-dev

# Install per-component requirements (source of truth for each component)
COPY controller/requirements.txt controller/requirements.txt
COPY webui/requirements.txt webui/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r controller/requirements.txt -r webui/requirements.txt

# Controller source
COPY controller/ controller/

# WebUI source (static/templates included via directory copy)
COPY webui/ webui/

# Run as non-root — pin UID/GID to 1000 to match Helm securityContext
RUN addgroup -g 1000 -S k8s-janus && \
    adduser -u 1000 -S -G k8s-janus -H -s /sbin/nologin k8s-janus

USER 1000

# Default — overridden per-deployment via Helm command:
# controller: kopf run /app/controller/main.py --all-namespaces --liveness=http://0.0.0.0:8080/healthz
# webui:      uvicorn main:app --app-dir /app/webui --host 0.0.0.0 --port 8000
CMD ["kopf", "run", "/app/controller/main.py", "--all-namespaces", "--liveness=http://0.0.0.0:8080/healthz"]
