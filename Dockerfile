FROM python:3.12-alpine

WORKDIR /app

# Build deps for psycopg2-binary and native extensions
RUN apk add --no-cache libpq gcc musl-dev supervisor

# Combined requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Controller source
COPY controller/ controller/

# WebUI source (static/templates included via directory copy)
COPY webui/ webui/

# Supervisord config
COPY supervisord.conf /etc/supervisor/conf.d/k8s-janus.conf

# Run as non-root — pin UID/GID to 1000 to match Helm securityContext
RUN addgroup -g 1000 -S k8s-janus && \
    adduser -u 1000 -S -G k8s-janus -H -s /sbin/nologin k8s-janus

USER 1000

CMD ["sh", "-c", "mkdir -p /tmp/supervisor && exec supervisord -c /etc/supervisor/conf.d/k8s-janus.conf -n"]
