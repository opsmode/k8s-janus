#!/usr/bin/env python3
"""
Database migration script for K8s-Janus.

Run once before the application starts (Helm pre-install/pre-upgrade Job).
Idempotent — safe to run multiple times.

For PostgreSQL: uses CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN IF NOT EXISTS.
For SQLite (dev): delegates to SQLAlchemy create_all (no Job runs for SQLite).
"""
import os
import sys
import logging
from urllib.parse import quote_plus

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("db-migrate")


def _build_url() -> str:
    host = os.environ.get("DB_HOST", "")
    if not host:
        return "sqlite:////tmp/k8s-janus.db"
    port = os.environ.get("DB_PORT", "5432")
    name = os.environ.get("DB_NAME", "janus")
    user = quote_plus(os.environ.get("DB_USER", "janus"))
    pw   = quote_plus(os.environ.get("DB_PASSWORD", ""))
    return f"postgresql://{user}:{pw}@{host}:{port}/{name}"


# ---------------------------------------------------------------------------
# DDL statements (PostgreSQL)
# ---------------------------------------------------------------------------

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS access_requests (
    id               SERIAL PRIMARY KEY,
    name             VARCHAR(255) NOT NULL UNIQUE,
    cluster          VARCHAR(100) NOT NULL,
    namespace        VARCHAR(255) NOT NULL,
    requester        VARCHAR(255) NOT NULL,
    ttl_seconds      INTEGER NOT NULL,
    reason           TEXT,
    phase            VARCHAR(50)  NOT NULL,
    approved_by      VARCHAR(255),
    denial_reason    TEXT,
    created_at       TIMESTAMPTZ NOT NULL,
    approved_at      TIMESTAMPTZ,
    active_at        TIMESTAMPTZ,
    expired_at       TIMESTAMPTZ,
    denied_at        TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    service_account  VARCHAR(255),
    token_secret     VARCHAR(255),
    expires_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_access_requests_name      ON access_requests (name);
CREATE INDEX IF NOT EXISTS ix_access_requests_cluster   ON access_requests (cluster);
CREATE INDEX IF NOT EXISTS ix_access_requests_namespace ON access_requests (namespace);
CREATE INDEX IF NOT EXISTS ix_access_requests_requester ON access_requests (requester);
CREATE INDEX IF NOT EXISTS ix_access_requests_phase     ON access_requests (phase);
CREATE INDEX IF NOT EXISTS ix_access_requests_created   ON access_requests (created_at);

CREATE TABLE IF NOT EXISTS audit_logs (
    id           SERIAL PRIMARY KEY,
    request_name VARCHAR(255) NOT NULL,
    event        VARCHAR(100) NOT NULL,
    actor        VARCHAR(255),
    timestamp    TIMESTAMPTZ NOT NULL,
    detail       TEXT
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_request_name ON audit_logs (request_name);
CREATE INDEX IF NOT EXISTS ix_audit_logs_event        ON audit_logs (event);
CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp    ON audit_logs (timestamp);

CREATE TABLE IF NOT EXISTS terminal_commands (
    id           SERIAL PRIMARY KEY,
    request_name VARCHAR(255) NOT NULL,
    pod          VARCHAR(255) NOT NULL,
    command      TEXT NOT NULL,
    timestamp    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_terminal_commands_request_name ON terminal_commands (request_name);
CREATE INDEX IF NOT EXISTS ix_terminal_commands_timestamp    ON terminal_commands (timestamp);

CREATE TABLE IF NOT EXISTS user_quick_commands (
    id         SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    label      VARCHAR(100) NOT NULL,
    command    TEXT NOT NULL,
    position   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_user_quick_commands_user_email ON user_quick_commands (user_email);
"""

# Incremental columns added after initial schema — safe to re-run
_ADD_COLUMNS: list[tuple[str, str, str]] = [
    # (table, column, definition)
    # Example for future migrations:
    # ("access_requests", "extra_field", "VARCHAR(255)"),
]


def run_migrations(url: str) -> None:
    import sqlalchemy as sa

    is_pg = url.startswith("postgresql")
    engine = sa.create_engine(url, pool_pre_ping=True,
                               connect_args={"connect_timeout": 10} if is_pg else {})

    with engine.begin() as conn:
        if is_pg:
            log.info("Running PostgreSQL migrations...")
            conn.execute(sa.text(_CREATE_TABLES))

            for table, col, defn in _ADD_COLUMNS:
                result = conn.execute(sa.text(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_name=:t AND column_name=:c"
                ), {"t": table, "c": col})
                if not result.fetchone():
                    log.info(f"  ALTER TABLE {table} ADD COLUMN {col} {defn}")
                    conn.execute(sa.text(
                        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {defn}"
                    ))
        else:
            # SQLite: delegate to SQLAlchemy (used in local dev only, no Job runs)
            from db import Base
            Base.metadata.create_all(engine)

    log.info("Migrations complete.")


if __name__ == "__main__":
    url = _build_url()
    log.info(f"DB: {url.split('@')[-1] if '@' in url else url}")
    try:
        run_migrations(url)
    except Exception as e:
        log.error(f"Migration failed: {e}")
        sys.exit(1)
