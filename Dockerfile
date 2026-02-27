FROM python:3.12-alpine

WORKDIR /app

# Build deps for psycopg2-binary and native extensions
RUN apk add --no-cache libpq gcc musl-dev

# Combined requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

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
