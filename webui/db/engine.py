"""
Database engine, session factory, and init for K8s-Janus.
"""

import os
import logging
from datetime import datetime, timezone
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from db.models import Base

logger = logging.getLogger("k8s-janus.db")

# ---------------------------------------------------------------------------
# Engine setup
# ---------------------------------------------------------------------------

def _build_url() -> str:
    host = os.environ.get("DB_HOST", "")
    if host:
        from urllib.parse import quote_plus
        port = os.environ.get("DB_PORT", "5432")
        name = os.environ.get("DB_NAME", "janus")
        user = quote_plus(os.environ.get("DB_USER", "janus"))
        pw   = quote_plus(os.environ.get("DB_PASSWORD", ""))
        return f"postgresql://{user}:{pw}@{host}:{port}/{name}"
    # Fallback: SQLite on the emptyDir /tmp volume
    return "sqlite:////tmp/k8s-janus.db"


_engine = None
_SessionLocal = None
db_enabled: bool = False


def init_db() -> None:
    """Call once at application startup."""
    global _engine, _SessionLocal, db_enabled
    url = _build_url()
    is_pg = url.startswith("postgresql")
    try:
        kwargs: dict = {"pool_pre_ping": True}
        if is_pg:
            kwargs["pool_size"] = 5
            kwargs["max_overflow"] = 10
            kwargs["connect_args"] = {
                "connect_timeout": 5,
                "options": "-c statement_timeout=10000",  # 10s query timeout
            }
        else:
            # SQLite: no pool, check_same_thread=False for async use
            kwargs["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(url, **kwargs)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
        # create_all is idempotent (CREATE TABLE IF NOT EXISTS semantics) — safe on every
        # startup. The Helm init-db Job also runs db_migrate.py for additive migrations,
        # but ArgoCD skips Helm hooks so startup creation is the reliable baseline.
        Base.metadata.create_all(_engine)
        db_enabled = True
        backend = "PostgreSQL" if is_pg else "SQLite (ephemeral)"
        logger.info(f"DB initialised ({backend})")
    except Exception as e:
        logger.error(f"DB init failed — persistence disabled: {e}")
        db_enabled = False


@contextmanager
def get_session() -> Session:
    if not db_enabled or _SessionLocal is None:
        yield None  # callers must check for None
        return
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)
