"""
db package — re-exports everything from the old flat db.py for backward compatibility.

Usage (unchanged):
    from db import init_db, upsert_request, log_audit, db_enabled, ...
"""

from db.engine import (
    init_db,
    get_session,
    _now,
)


def __getattr__(name: str):
    """Live proxy for db.engine module-level vars (e.g. db_enabled) so callers
    always see the current value rather than the snapshot taken at import time."""
    if name == "db_enabled":
        import db.engine as _engine
        return _engine.db_enabled
    raise AttributeError(f"module 'db' has no attribute {name!r}")

from db.queries import (
    upsert_request,
    log_audit,
    get_audit_log,
    get_recent_audit_logs,
    log_command,
    get_session_commands,
    purge_old_records,
    get_user_quick_commands,
    create_user_quick_command,
    update_user_quick_command,
    delete_user_quick_command,
    get_user_profile,
    save_user_profile,
)

from db.models import (
    Base,
    AccessRequestRecord,
    AuditLog,
    TerminalCommand,
    UserQuickCommand,
    UserProfile,
    LocalUser,
)

__all__ = [
    # engine
    "init_db",
    "get_session",
    "db_enabled",
    "_now",
    # queries
    "upsert_request",
    "log_audit",
    "get_audit_log",
    "get_recent_audit_logs",
    "log_command",
    "get_session_commands",
    "purge_old_records",
    "get_user_quick_commands",
    "create_user_quick_command",
    "update_user_quick_command",
    "delete_user_quick_command",
    "get_user_profile",
    "save_user_profile",
    # models
    "Base",
    "AccessRequestRecord",
    "AuditLog",
    "TerminalCommand",
    "UserQuickCommand",
    "UserProfile",
    "LocalUser",
]
