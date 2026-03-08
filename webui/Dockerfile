FROM python:3.12-alpine

WORKDIR /app

# Upgrade all Alpine packages to pick up latest security patches
# (CVE-2025-60876 busybox, CVE-2026-22184/27171 zlib)
RUN apk upgrade --no-cache

# Install build deps for psycopg2-binary and other native extensions
RUN apk add --no-cache libpq gcc musl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root user
RUN adduser -D -H -s /sbin/nologin appuser
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
