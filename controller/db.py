"""
Persistence layer for K8s-Janus.

When postgresql.enabled=true the controller and webui both have DB_HOST/DB_PASSWORD
injected as env vars. Otherwise falls back to a SQLite file at /tmp/k8s-janus.db
(the emptyDir volume already mounted on both pods).

Usage:
    from db import db_enabled, get_session, upsert_request, log_audit

All public functions are no-ops when the DB engine cannot be initialised.
"""

import os
import logging
from datetime import datetime, timezone
from contextlib import contextmanager

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Text, JSON,
    UniqueConstraint, text,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

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
            kwargs["connect_args"] = {"connect_timeout": 5}
        else:
            # SQLite: no pool, check_same_thread=False for async use
            kwargs["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(url, **kwargs)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
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


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class AccessRequestRecord(Base):
    __tablename__ = "access_requests"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String(255), unique=True, nullable=False, index=True)
    cluster      = Column(String(100), nullable=False, index=True)
    namespace    = Column(String(255), nullable=False, index=True)
    requester    = Column(String(255), nullable=False, index=True)
    ttl_seconds  = Column(Integer, nullable=False)
    reason       = Column(Text)
    phase        = Column(String(50), nullable=False, index=True)
    approved_by  = Column(String(255))
    denial_reason= Column(Text)
    created_at   = Column(DateTime(timezone=True), nullable=False, index=True)
    approved_at  = Column(DateTime(timezone=True))
    active_at    = Column(DateTime(timezone=True))
    expired_at   = Column(DateTime(timezone=True))
    denied_at    = Column(DateTime(timezone=True))
    revoked_at   = Column(DateTime(timezone=True))
    service_account = Column(String(255))
    token_secret    = Column(String(255))
    expires_at      = Column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    request_name = Column(String(255), nullable=False, index=True)
    event        = Column(String(100), nullable=False, index=True)
    actor        = Column(String(255))
    timestamp    = Column(DateTime(timezone=True), nullable=False, index=True)
    detail       = Column(Text)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def upsert_request(name: str, **fields) -> None:
    """Insert or update an AccessRequestRecord row.

    On insert: all fields are written.
    On update: created_at is never overwritten (preserves original creation time).
    """
    if not db_enabled:
        return
    try:
        with get_session() as session:
            if session is None:
                return
            rec = session.query(AccessRequestRecord).filter_by(name=name).first()
            if rec is None:
                rec = AccessRequestRecord(name=name, **fields)
                session.add(rec)
            else:
                for k, v in fields.items():
                    if k == "created_at":
                        continue  # never overwrite original creation time
                    setattr(rec, k, v)
    except Exception as e:
        logger.error(f"upsert_request({name}) failed: {e}")


def log_audit(request_name: str, event: str, actor: str = "", detail: str = "") -> None:
    """Append a row to audit_logs."""
    if not db_enabled:
        return
    try:
        with get_session() as session:
            if session is None:
                return
            session.add(AuditLog(
                request_name=request_name,
                event=event,
                actor=actor,
                timestamp=_now(),
                detail=detail,
            ))
    except Exception as e:
        logger.error(f"log_audit({request_name}, {event}) failed: {e}")


def get_audit_log(request_name: str) -> list[dict]:
    """Return audit log entries for a specific request, oldest first."""
    if not db_enabled:
        return []
    try:
        with get_session() as session:
            if session is None:
                return []
            rows = (
                session.query(AuditLog)
                .filter_by(request_name=request_name)
                .order_by(AuditLog.timestamp)
                .all()
            )
            return [
                {
                    "event": r.event,
                    "actor": r.actor,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                    "detail": r.detail,
                }
                for r in rows
            ]
    except Exception as e:
        logger.error(f"get_audit_log({request_name}) failed: {e}")
        return []


def get_recent_audit_logs(limit: int = 200) -> list[dict]:
    """Return the most recent audit log entries across all requests."""
    if not db_enabled:
        return []
    try:
        with get_session() as session:
            if session is None:
                return []
            rows = (
                session.query(AuditLog)
                .order_by(AuditLog.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "request_name": r.request_name,
                    "event": r.event,
                    "actor": r.actor,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                    "detail": r.detail,
                }
                for r in rows
            ]
    except Exception as e:
        logger.error(f"get_recent_audit_logs() failed: {e}")
        return []
