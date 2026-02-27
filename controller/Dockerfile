FROM python:3.12-alpine

WORKDIR /app

# Install build deps for psycopg2-binary and other native extensions
RUN apk add --no-cache libpq gcc musl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY db.py .

# Run as non-root user
RUN adduser -D -H -s /sbin/nologin appuser
USER appuser

CMD ["kopf", "run", "/app/main.py", "--all-namespaces", "--liveness=http://0.0.0.0:8080/healthz"]
