FROM python:3.12-alpine AS builder

WORKDIR /build

# Build deps only — gcc/binutils stay in this stage and never reach the runtime image
RUN apk add --no-cache gcc musl-dev libpq-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-alpine

ARG BUILD_DATE=unknown
ENV BUILD_DATE=${BUILD_DATE}

WORKDIR /app

# Upgrade all Alpine packages to pick up latest security patches
RUN apk upgrade --no-cache

# Runtime-only native libs (no compiler)
RUN apk add --no-cache libpq

# Copy compiled packages from builder
COPY --from=builder /install /usr/local

COPY . .

RUN adduser -D -H -s /sbin/nologin appuser
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
