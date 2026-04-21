"""
Query functions for K8s-Janus persistence layer.
"""

import logging

from sqlalchemy.exc import IntegrityError

from db.models import (
    AccessRequestRecord, AuditLog, TerminalCommand,
    UserQuickCommand, UserProfile,
)
import db.engine as _db_engine
from db.engine import get_session, _now


def _db_enabled() -> bool:
    return _db_engine.db_enabled


logger = logging.getLogger("k8s-janus.db")


# ---------------------------------------------------------------------------
# Access requests
# ---------------------------------------------------------------------------

def upsert_request(name: str, **fields) -> None:
    """Insert or update an AccessRequestRecord row.

    On insert: all fields are written.
    On update: created_at is never overwritten (preserves original creation time).
    """
    if not _db_enabled():
        return
    try:
        with get_session() as session:
            if session is None:
                return
            rec = session.query(AccessRequestRecord).filter_by(name=name).first()
            if rec is None:
                try:
                    rec = AccessRequestRecord(name=name, **fields)
                    session.add(rec)
                    session.flush()
                except IntegrityError:
                    # Concurrent insert raced us — fall back to update
                    session.rollback()
                    rec = session.query(AccessRequestRecord).filter_by(name=name).first()
                    if rec:
                        for k, v in fields.items():
                            if k != "created_at":
                                setattr(rec, k, v)
            else:
                for k, v in fields.items():
                    if k == "created_at":
                        continue  # never overwrite original creation time
                    setattr(rec, k, v)
    except Exception as e:
        logger.error(f"upsert_request({name}) failed: {e}")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def log_audit(request_name: str, event: str, actor: str = "", detail: str = "") -> None:
    """Append a row to audit_logs."""
    if not _db_enabled():
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
    if not _db_enabled():
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


def get_recent_audit_logs(limit: int = 200, offset: int = 0) -> list[dict]:
    """Return the most recent audit log entries across all requests, with pagination."""
    if not _db_enabled():
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


# ---------------------------------------------------------------------------
# Terminal commands
# ---------------------------------------------------------------------------

def log_command(request_name: str, pod: str, command: str) -> None:
    """Append a typed command to terminal_commands."""
    if not _db_enabled():
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
    if not _db_enabled():
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


def purge_old_records(days: int = 30) -> int:
    """Delete terminal_commands and audit_logs older than N days. Returns total rows deleted."""
    if not _db_enabled():
        return 0
    from datetime import timedelta
    cutoff = _now() - timedelta(days=days)
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
    if not _db_enabled():
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
    if not _db_enabled():
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
    if not _db_enabled():
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
    if not _db_enabled():
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
# User Profiles (for HA multi-replica deployments)
# ---------------------------------------------------------------------------

def get_user_profile(user_email: str) -> dict:
    """Get profile for user. Returns {"name": "", "photo": ""} if not found."""
    if not _db_enabled():
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
    if not _db_enabled():
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
