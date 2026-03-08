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

# Point APP_DIR at the local webui directory so StaticFiles mount doesn't fail
_WEBUI_DIR = os.path.join(os.path.dirname(__file__), "..")
os.environ.setdefault("APP_DIR", os.path.abspath(_WEBUI_DIR))
sys.path.insert(0, os.path.abspath(_WEBUI_DIR))

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import ASGITransport, AsyncClient

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
# Base patcher — always mock k8s + db side effects
# ---------------------------------------------------------------------------
BASE_PATCHES = {
    "main.get_clusters":        MagicMock(return_value=FAKE_CLUSTERS),
    "main.list_access_requests": MagicMock(return_value=[]),
    "main.log_audit":           MagicMock(),
    "main.upsert_request":      MagicMock(),
    "main.notify_revoked":      AsyncMock(),
    # Prevent startup k8s calls
    "main.init_db":             MagicMock(),
}


def _apply_patches(monkeypatch, extra=None):
    """Apply BASE_PATCHES + any extra {dotted.name: mock} overrides."""
    patches = {**BASE_PATCHES, **(extra or {})}
    for target, mock in patches.items():
        module, attr = target.rsplit(".", 1)
        monkeypatch.setattr(f"{module}.{attr}", mock, raising=False)


# ---------------------------------------------------------------------------
# Auth helpers — return headers dict
# ---------------------------------------------------------------------------
def admin_headers():
    return {"X-Forwarded-Email": ADMIN_EMAIL, "X-Forwarded-User": "Admin"}

def user_headers():
    return {"X-Forwarded-Email": USER_EMAIL, "X-Forwarded-User": "User"}


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------
@pytest.fixture
def open_client(monkeypatch):
    """TestClient with auth disabled (open mode — everyone is admin)."""
    _apply_patches(monkeypatch)
    import main
    monkeypatch.setattr(main, "AUTH_ENABLED",  False)
    monkeypatch.setattr(main, "OIDC_ENABLED",  False)
    monkeypatch.setattr(main, "ADMIN_EMAILS",  set())
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def admin_client(monkeypatch):
    """TestClient with auth enabled, caller is admin."""
    _apply_patches(monkeypatch)
    import main
    monkeypatch.setattr(main, "AUTH_ENABLED",  True)
    monkeypatch.setattr(main, "OIDC_ENABLED",  False)
    monkeypatch.setattr(main, "ADMIN_EMAILS",  {ADMIN_EMAIL})
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        c.headers.update(admin_headers())
        yield c


@pytest.fixture
def user_client(monkeypatch):
    """TestClient with auth enabled, caller is regular user (not admin)."""
    _apply_patches(monkeypatch)
    import main
    monkeypatch.setattr(main, "AUTH_ENABLED",  True)
    monkeypatch.setattr(main, "OIDC_ENABLED",  False)
    monkeypatch.setattr(main, "ADMIN_EMAILS",  {ADMIN_EMAIL})
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        c.headers.update(user_headers())
        yield c


@pytest.fixture
def anon_client(monkeypatch):
    """TestClient with auth enabled, no credentials."""
    _apply_patches(monkeypatch)
    import main
    monkeypatch.setattr(main, "AUTH_ENABLED",  True)
    monkeypatch.setattr(main, "OIDC_ENABLED",  False)
    monkeypatch.setattr(main, "ADMIN_EMAILS",  {ADMIN_EMAIL})
    from starlette.testclient import TestClient
    with TestClient(main.app, raise_server_exceptions=False) as c:
        yield c
