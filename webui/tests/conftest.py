"""
Shared fixtures for K8s-Janus webui test suite.

Auth modes:
  - open_client:  AUTH_ENABLED=False + OIDC_ENABLED=False → every caller is admin
  - admin_client: AUTH_ENABLED=True  + OIDC_ENABLED=False → X-Forwarded-Email = admin@test.com
  - user_client:  AUTH_ENABLED=True  + OIDC_ENABLED=False → X-Forwarded-Email = user@test.com
  - anon_client:  AUTH_ENABLED=True  + OIDC_ENABLED=False → no header
"""

import os
import sys
from unittest.mock import MagicMock

_WEBUI_DIR = os.path.join(os.path.dirname(__file__), "..")
os.environ.setdefault("APP_DIR", os.path.abspath(_WEBUI_DIR))
sys.path.insert(0, os.path.abspath(_WEBUI_DIR))

# Stub heavy C-extension / network modules before any app code is imported.
_k8s_client                   = MagicMock()
_k8s_client.exceptions        = MagicMock()
_k8s_client.rest              = MagicMock()
_HEAVY = {
    "kubernetes":                            MagicMock(),
    "kubernetes.client":                     _k8s_client,
    "kubernetes.client.rest":                _k8s_client.rest,
    "kubernetes.client.exceptions":          _k8s_client.exceptions,
    "kubernetes.config":                     MagicMock(),
    "kubernetes.stream":                     MagicMock(),
    "authlib":                               MagicMock(),
    "authlib.integrations":                  MagicMock(),
    "authlib.integrations.starlette_client": MagicMock(),
}
for _mod, _mock in _HEAVY.items():
    sys.modules.setdefault(_mod, _mock)

import pytest
from unittest.mock import AsyncMock, MagicMock

ADMIN_EMAIL = "admin@test.com"
USER_EMAIL  = "user@test.com"
CLUSTER     = "central"
REQ_NAME    = "janus-req-test-0101000000"

FAKE_CLUSTERS = [{"name": CLUSTER, "displayName": CLUSTER}]


def fake_ar(name=REQ_NAME, cluster=CLUSTER, phase="Pending",
            requester=USER_EMAIL, namespaces=None, ttl=3600):
    return {
        "metadata": {"name": name, "creationTimestamp": "2026-01-01T00:00:00Z"},
        "spec": {
            "requester": requester,
            "namespaces": namespaces or ["default"],
            "ttlSeconds": ttl,
            "reason": "test reason",
        },
        "status": {"phase": phase, "approvedBy": "", "expiresAt": ""},
        "_cluster": cluster,
        "_clusterDisplay": cluster,
    }


# ---------------------------------------------------------------------------
# Base patcher — patch at source modules so all routers see the mock
# ---------------------------------------------------------------------------
BASE_PATCHES = {
    # k8s module — all routers import from here
    "k8s.get_clusters":          MagicMock(return_value=FAKE_CLUSTERS),
    "k8s.list_access_requests":  MagicMock(return_value=[]),
    # db module — all routers import from here
    "db.log_audit":              MagicMock(),
    "db.upsert_request":         MagicMock(),
    # terminal_ws
    "terminal_ws.notify_revoked": AsyncMock(),
    # startup
    "main.init_db":              MagicMock(),
}


def _apply_patches(monkeypatch, extra=None):
    patches = {**BASE_PATCHES, **(extra or {})}
    for target, mock in patches.items():
        module, attr = target.rsplit(".", 1)
        monkeypatch.setattr(f"{module}.{attr}", mock, raising=False)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def admin_headers():
    return {"X-Forwarded-Email": ADMIN_EMAIL, "X-Forwarded-User": "Admin"}

def user_headers():
    return {"X-Forwarded-Email": USER_EMAIL, "X-Forwarded-User": "User"}


def _set_auth_mode(monkeypatch, oidc=False, local=False, admin_emails=None):
    """Patch auth config in all the places that use it."""
    import main
    import core.config
    import core.auth
    monkeypatch.setattr(main,        "OIDC_ENABLED",       oidc)
    monkeypatch.setattr(main,        "LOCAL_AUTH_ENABLED",  local)
    monkeypatch.setattr(core.config, "OIDC_ENABLED",       oidc)
    monkeypatch.setattr(core.config, "LOCAL_AUTH_ENABLED",  local)
    monkeypatch.setattr(core.auth,   "LOCAL_AUTH_ENABLED",  local)
    emails = admin_emails if admin_emails is not None else set()
    monkeypatch.setattr(core.config, "ADMIN_EMAILS",        emails)
    monkeypatch.setattr(core.auth,   "ADMIN_EMAILS",        emails)


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------
@pytest.fixture
def open_client(monkeypatch):
    """TestClient with auth disabled (open mode — pass-through, everyone treated as admin)."""
    _apply_patches(monkeypatch)
    _set_auth_mode(monkeypatch, oidc=False, local=False, admin_emails=set())
    import main
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def admin_client(monkeypatch):
    """TestClient with X-Forwarded-Email auth, caller is admin."""
    _apply_patches(monkeypatch)
    _set_auth_mode(monkeypatch, oidc=False, local=False, admin_emails={ADMIN_EMAIL})
    import main
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        c.headers.update(admin_headers())
        yield c


@pytest.fixture
def user_client(monkeypatch):
    """TestClient with X-Forwarded-Email auth, caller is regular user."""
    _apply_patches(monkeypatch)
    _set_auth_mode(monkeypatch, oidc=False, local=False, admin_emails={ADMIN_EMAIL})
    import main
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        c.headers.update(user_headers())
        yield c


@pytest.fixture
def anon_client(monkeypatch):
    """TestClient with X-Forwarded-Email auth, no credentials."""
    _apply_patches(monkeypatch)
    _set_auth_mode(monkeypatch, oidc=False, local=False, admin_emails={ADMIN_EMAIL})
    import main
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        yield c
