"""
DB layer tests using SQLite in-memory.
Tests run against real SQLAlchemy models — no mocking of db internals.
"""
import os
import pytest
from datetime import datetime, timezone

# Force SQLite in-memory for all DB tests (must be set before 'import db')
os.environ.setdefault("DB_HOST", "")

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ar(name, phase="Pending", cluster="c", namespace="ns",
        requester="u@t.com", ttl_seconds=3600, created_at=None, **kwargs):
    """Helper: call upsert_request with sensible defaults."""
    from db import upsert_request
    upsert_request(name, phase=phase, cluster=cluster, namespace=namespace,
                   requester=requester, ttl_seconds=ttl_seconds,
                   created_at=created_at or _NOW, **kwargs)


@pytest.fixture(autouse=True)
def fresh_db():
    """Reinitialize DB with a fresh in-memory SQLite for every test."""
    import db
    import db.engine as _db_engine
    import db.queries as _db_queries
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    db.Base.metadata.create_all(engine)
    _db_engine._engine = engine
    _db_engine._SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    _db_engine.db_enabled = True
    _db_queries.db_enabled = True
    yield
    db.Base.metadata.drop_all(engine)
    engine.dispose()
    _db_engine.db_enabled = False
    _db_queries.db_enabled = False


# ---------------------------------------------------------------------------
# upsert_request
# ---------------------------------------------------------------------------
class TestUpsertRequest:

    def test_insert_new_record(self):
        from db import get_session, AccessRequestRecord
        _ar("req-001", phase="Pending", requester="user@test.com", cluster="central", namespace="default")
        with get_session() as s:
            rec = s.query(AccessRequestRecord).filter_by(name="req-001").first()
            assert rec is not None
            assert rec.phase == "Pending"
            assert rec.requester == "user@test.com"

    def test_update_existing_phase(self):
        from db import upsert_request, get_session, AccessRequestRecord
        _ar("req-002")
        upsert_request("req-002", phase="Approved", approved_by="admin@t.com",
                       cluster="c", namespace="ns", requester="u@t.com",
                       ttl_seconds=3600, created_at=_NOW)
        with get_session() as s:
            rec = s.query(AccessRequestRecord).filter_by(name="req-002").first()
            assert rec.phase == "Approved"
            assert rec.approved_by == "admin@t.com"

    def test_created_at_not_overwritten_on_update(self):
        from db import upsert_request, get_session, AccessRequestRecord
        t = datetime(2026, 1, 1, tzinfo=timezone.utc)
        _ar("req-003", created_at=t)
        # Second upsert with a different created_at should not overwrite
        upsert_request("req-003", phase="Approved", cluster="c", namespace="ns",
                       requester="u@t.com", ttl_seconds=3600,
                       created_at=datetime(2026, 6, 1, tzinfo=timezone.utc))
        with get_session() as s:
            rec = s.query(AccessRequestRecord).filter_by(name="req-003").first()
            # SQLite strips tzinfo; compare naive datetimes
            assert rec.created_at.replace(tzinfo=None) == t.replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
class TestAuditLog:

    def test_log_and_retrieve(self):
        from db import log_audit, get_audit_log
        log_audit("req-a", "request.created", actor="user@t.com", detail="cluster=c")
        log_audit("req-a", "request.approved", actor="admin@t.com", detail="cluster=c")
        entries = get_audit_log("req-a")
        assert len(entries) == 2
        assert entries[0]["event"] == "request.created"
        assert entries[1]["event"] == "request.approved"

    def test_get_recent_audit_logs_pagination(self):
        from db import log_audit, get_recent_audit_logs
        for i in range(5):
            log_audit(f"req-{i}", "request.created", actor="u@t.com")
        page1 = get_recent_audit_logs(limit=3, offset=0)
        page2 = get_recent_audit_logs(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2
        # No overlap
        names1 = {e["request_name"] for e in page1}
        names2 = {e["request_name"] for e in page2}
        assert names1.isdisjoint(names2)

    def test_audit_for_unknown_request_returns_empty(self):
        from db import get_audit_log
        assert get_audit_log("nonexistent") == []


# ---------------------------------------------------------------------------
# Quick commands
# ---------------------------------------------------------------------------
class TestQuickCommands:

    def test_create_and_list(self):
        from db import create_user_quick_command, get_user_quick_commands
        result = create_user_quick_command("u@t.com", "Get pods", "kubectl get pods")
        assert result is not None
        assert result["label"] == "Get pods"
        cmds = get_user_quick_commands("u@t.com")
        assert len(cmds) == 1
        assert cmds[0]["command"] == "kubectl get pods"

    def test_update(self):
        from db import create_user_quick_command, update_user_quick_command, get_user_quick_commands
        cmd = create_user_quick_command("u@t.com", "Old label", "old cmd")
        ok = update_user_quick_command("u@t.com", cmd["id"], "New label", "new cmd")
        assert ok is True
        cmds = get_user_quick_commands("u@t.com")
        assert cmds[0]["label"] == "New label"
        assert cmds[0]["command"] == "new cmd"

    def test_delete(self):
        from db import create_user_quick_command, delete_user_quick_command, get_user_quick_commands
        cmd = create_user_quick_command("u@t.com", "To delete", "del cmd")
        ok = delete_user_quick_command("u@t.com", cmd["id"])
        assert ok is True
        assert get_user_quick_commands("u@t.com") == []

    def test_delete_wrong_user_fails(self):
        from db import create_user_quick_command, delete_user_quick_command
        cmd = create_user_quick_command("owner@t.com", "Mine", "cmd")
        ok = delete_user_quick_command("other@t.com", cmd["id"])
        assert ok is False

    def test_list_empty_for_new_user(self):
        from db import get_user_quick_commands
        assert get_user_quick_commands("nobody@t.com") == []


# ---------------------------------------------------------------------------
# Command history
# ---------------------------------------------------------------------------
class TestCommandHistory:

    def test_log_and_retrieve(self):
        from db import log_command, get_session_commands
        log_command("req-h1", "pod-a", "ls -la")
        log_command("req-h1", "pod-a", "cat /etc/hosts")
        cmds = get_session_commands("req-h1")
        assert len(cmds) == 2
        assert cmds[0]["command"] == "ls -la"
        assert cmds[1]["command"] == "cat /etc/hosts"

    def test_history_isolated_per_request(self):
        from db import log_command, get_session_commands
        log_command("req-x", "pod", "cmd-x")
        log_command("req-y", "pod", "cmd-y")
        assert len(get_session_commands("req-x")) == 1
        assert len(get_session_commands("req-y")) == 1
