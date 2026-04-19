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
    create_engine, Column, Integer, String, DateTime, Text, Boolean,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from cryptography.fernet import Fernet

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


class TerminalCommand(Base):
    __tablename__ = "terminal_commands"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    request_name = Column(String(255), nullable=False, index=True)
    pod          = Column(String(255), nullable=False)
    command      = Column(Text, nullable=False)
    timestamp    = Column(DateTime(timezone=True), nullable=False, index=True)


class UserQuickCommand(Base):
    __tablename__ = "user_quick_commands"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String(255), nullable=False, index=True)
    label      = Column(String(100), nullable=False)
    command    = Column(Text, nullable=False)
    position   = Column(Integer, nullable=False, default=0)


class UserMFA(Base):
    __tablename__ = "user_mfa"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    user_email   = Column(String(255), unique=True, nullable=False, index=True)
    enabled      = Column(Boolean, nullable=False, default=False)
    totp_secret  = Column(Text, nullable=True)  # Encrypted with Fernet
    backup_codes = Column(Text, nullable=True)  # Encrypted JSON array
    created_at   = Column(DateTime(timezone=True), nullable=False)
    last_used_at = Column(DateTime(timezone=True))


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String(255), unique=True, nullable=False, index=True)
    name       = Column(String(100))
    photo      = Column(Text)  # Base64 data URL
    updated_at = Column(DateTime(timezone=True), nullable=False)


class LocalUser(Base):
    __tablename__ = "local_users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    email         = Column(String(255), unique=True, nullable=False, index=True)
    name          = Column(String(100), nullable=False)
    password_hash = Column(Text, nullable=False)
    is_admin      = Column(Boolean, nullable=False, default=False)
    is_active     = Column(Boolean, nullable=False, default=True)
    created_at    = Column(DateTime(timezone=True), nullable=False)


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
                actor=actor[:255] if actor else actor,
                timestamp=_now(),
                detail=detail[:1000] if detail else detail,
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


def log_command(request_name: str, pod: str, command: str) -> None:
    """Append a typed command to terminal_commands."""
    if not db_enabled:
        return
    try:
        with get_session() as session:
            if session is None:
                return
            session.add(TerminalCommand(
                request_name=request_name,
                pod=pod,
                command=command,
                timestamp=_now(),
            ))
    except Exception as e:
        logger.error(f"log_command({request_name}) failed: {e}")


def get_session_commands(request_name: str) -> list[dict]:
    """Return all typed commands for a request, oldest first."""
    if not db_enabled:
        return []
    try:
        with get_session() as session:
            if session is None:
                return []
            rows = (
                session.query(TerminalCommand)
                .filter_by(request_name=request_name)
                .order_by(TerminalCommand.timestamp)
                .all()
            )
            return [
                {
                    "pod": r.pod,
                    "command": r.command,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                }
                for r in rows
            ]
    except Exception as e:
        logger.error(f"get_session_commands({request_name}) failed: {e}")
        return []


def get_recent_audit_logs(limit: int = 200, offset: int = 0) -> list[dict]:
    """Return the most recent audit log entries across all requests, with pagination."""
    if not db_enabled:
        return []
    try:
        with get_session() as session:
            if session is None:
                return []
            rows = (
                session.query(AuditLog)
                .order_by(AuditLog.timestamp.desc())
                .offset(offset)
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


def purge_old_records(days: int = 30) -> int:
    """Delete terminal_commands and audit_logs older than N days. Returns total rows deleted."""
    if not db_enabled:
        return 0
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = 0
    try:
        with get_session() as session:
            if session is None:
                return 0
            deleted += session.query(TerminalCommand).filter(TerminalCommand.timestamp < cutoff).delete()
            deleted += session.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete()
        logger.info(f"Purged {deleted} old DB records older than {days} days")
    except Exception as e:
        logger.error(f"purge_old_records() failed: {e}")
    return deleted


# ---------------------------------------------------------------------------
# User quick commands
# ---------------------------------------------------------------------------

def get_user_quick_commands(user_email: str) -> list[dict]:
    if not db_enabled:
        return []
    try:
        with get_session() as session:
            if session is None:
                return []
            rows = (
                session.query(UserQuickCommand)
                .filter_by(user_email=user_email)
                .order_by(UserQuickCommand.position, UserQuickCommand.id)
                .all()
            )
            return [{"id": r.id, "label": r.label, "command": r.command, "position": r.position}
                    for r in rows]
    except Exception as e:
        logger.error(f"get_user_quick_commands({user_email}) failed: {e}")
        return []


def create_user_quick_command(user_email: str, label: str, command: str) -> dict | None:
    if not db_enabled:
        return None
    try:
        with get_session() as session:
            if session is None:
                return None
            max_pos = (session.query(UserQuickCommand)
                       .filter_by(user_email=user_email)
                       .count())
            rec = UserQuickCommand(user_email=user_email, label=label,
                                   command=command, position=max_pos)
            session.add(rec)
            session.flush()
            return {"id": rec.id, "label": rec.label, "command": rec.command, "position": rec.position}
    except Exception as e:
        logger.error(f"create_user_quick_command({user_email}) failed: {e}")
        return None


def update_user_quick_command(user_email: str, cmd_id: int, label: str, command: str) -> bool:
    if not db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            rec = (session.query(UserQuickCommand)
                   .filter_by(id=cmd_id, user_email=user_email)
                   .first())
            if rec is None:
                return False
            rec.label   = label
            rec.command = command
            return True
    except Exception as e:
        logger.error(f"update_user_quick_command({user_email}, {cmd_id}) failed: {e}")
        return False


def delete_user_quick_command(user_email: str, cmd_id: int) -> bool:
    if not db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            deleted = (session.query(UserQuickCommand)
                       .filter_by(id=cmd_id, user_email=user_email)
                       .delete())
            return deleted > 0
    except Exception as e:
        logger.error(f"delete_user_quick_command({user_email}, {cmd_id}) failed: {e}")
        return False


# ---------------------------------------------------------------------------
# MFA (Multi-Factor Authentication)
# ---------------------------------------------------------------------------

# Encryption key for TOTP secrets — read from env or generate (ephemeral)
_MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY", "")
if not _MFA_ENCRYPTION_KEY:
    _MFA_ENCRYPTION_KEY = Fernet.generate_key().decode()
    logger.error(
        "MFA_ENCRYPTION_KEY not set — TOTP secrets will be lost on pod restart. "
        "Generate a stable key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
        "and set it as a Kubernetes Secret mounted as MFA_ENCRYPTION_KEY env var."
    )

_fernet = Fernet(_MFA_ENCRYPTION_KEY.encode())


def _encrypt(plaintext: str) -> str:
    """Encrypt a string using Fernet."""
    return _fernet.encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string."""
    return _fernet.decrypt(ciphertext.encode()).decode()


def get_user_mfa(user_email: str) -> dict | None:
    """Returns {enabled, totp_secret, backup_codes, created_at, last_used_at} or None."""
    if not db_enabled:
        return None
    try:
        with get_session() as session:
            if session is None:
                return None
            rec = session.query(UserMFA).filter_by(user_email=user_email).first()
            if rec is None:
                return None
            import json
            totp_secret = _decrypt(rec.totp_secret) if rec.totp_secret else None
            backup_codes = json.loads(_decrypt(rec.backup_codes)) if rec.backup_codes else []
            return {
                "enabled": rec.enabled,
                "totp_secret": totp_secret,
                "backup_codes": backup_codes,
                "created_at": rec.created_at.isoformat() if rec.created_at else "",
                "last_used_at": rec.last_used_at.isoformat() if rec.last_used_at else "",
            }
    except Exception as e:
        logger.error(f"get_user_mfa({user_email}) failed: {e}")
        return None


def enable_user_mfa(user_email: str, totp_secret: str, backup_codes: list[str]) -> bool:
    """Enable MFA for user with TOTP secret and backup codes."""
    if not db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            import json
            rec = session.query(UserMFA).filter_by(user_email=user_email).first()
            if rec is None:
                rec = UserMFA(
                    user_email=user_email,
                    enabled=True,
                    totp_secret=_encrypt(totp_secret),
                    backup_codes=_encrypt(json.dumps(backup_codes)),
                    created_at=_now(),
                )
                session.add(rec)
            else:
                rec.enabled = True
                rec.totp_secret = _encrypt(totp_secret)
                rec.backup_codes = _encrypt(json.dumps(backup_codes))
                rec.created_at = _now()
            return True
    except Exception as e:
        logger.error(f"enable_user_mfa({user_email}) failed: {e}")
        return False


def disable_user_mfa(user_email: str) -> bool:
    """Disable MFA for user (clears secrets)."""
    if not db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            rec = session.query(UserMFA).filter_by(user_email=user_email).first()
            if rec is None:
                return True  # Already disabled
            rec.enabled = False
            rec.totp_secret = None
            rec.backup_codes = None
            return True
    except Exception as e:
        logger.error(f"disable_user_mfa({user_email}) failed: {e}")
        return False


def update_mfa_last_used(user_email: str) -> None:
    """Update last_used_at timestamp for MFA."""
    if not db_enabled:
        return
    try:
        with get_session() as session:
            if session is None:
                return
            rec = session.query(UserMFA).filter_by(user_email=user_email).first()
            if rec:
                rec.last_used_at = _now()
    except Exception as e:
        logger.error(f"update_mfa_last_used({user_email}) failed: {e}")


# ---------------------------------------------------------------------------
# User Profiles (for HA multi-replica deployments)
# ---------------------------------------------------------------------------

def get_user_profile(user_email: str) -> dict:
    """Get profile for user. Returns {"name": "", "photo": ""} if not found."""
    if not db_enabled:
        return {}
    try:
        with get_session() as session:
            if session is None:
                return {}
            rec = session.query(UserProfile).filter_by(user_email=user_email).first()
            if rec is None:
                return {}
            return {"name": rec.name or "", "photo": rec.photo or ""}
    except Exception as e:
        logger.error(f"get_user_profile({user_email}) failed: {e}")
        return {}


def save_user_profile(user_email: str, name: str, photo: str) -> bool:
    """Save profile for user."""
    if not db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            rec = session.query(UserProfile).filter_by(user_email=user_email).first()
            if rec is None:
                rec = UserProfile(user_email=user_email, name=name, photo=photo, updated_at=_now())
                session.add(rec)
            else:
                rec.name = name
                rec.photo = photo
                rec.updated_at = _now()
            return True
    except Exception as e:
        logger.error(f"save_user_profile({user_email}) failed: {e}")
        return False
