FROM python:3.12-slim@sha256:39e4e1ccb01578e3c86f7a0cf7b7fd89b8dbe2c27a88de11cf726ba669469f49

WORKDIR /app

# Upgrade OS packages to patch known CVEs before installing app deps
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY db.py .

# Run as non-root user
RUN useradd --no-create-home --shell /bin/false appuser
USER appuser

CMD ["kopf", "run", "/app/main.py", "--all-namespaces", "--liveness=http://0.0.0.0:8080/healthz"]
