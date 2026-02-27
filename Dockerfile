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

# Run as non-root
RUN addgroup -S k8s-janus && adduser -S -G k8s-janus -H -s /sbin/nologin k8s-janus && \
    mkdir -p /tmp/supervisor && chown k8s-janus:k8s-janus /tmp/supervisor

USER k8s-janus

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/k8s-janus.conf", "-n"]
