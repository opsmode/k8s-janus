"""
Tests for auth gating in X-Forwarded-Email mode (AUTH_ENABLED=True, OIDC_ENABLED=False).

In this mode:
- No X-Forwarded-Email header → anonymous user (empty email, not in ADMIN_EMAILS)
- Anonymous user on admin-only routes → 403 (not admin)
- Anonymous user on pages → 200 (rendered with empty user context)
- Regular user on admin-only routes → 403
- Admin user on admin-only routes → 200
- /healthz is always public
"""
from .conftest import CLUSTER, REQ_NAME, fake_ar


class TestUnauthenticated:
    """Anonymous requests (no X-Forwarded-Email header) in AUTH_ENABLED mode."""

    def test_page_renders_for_anon(self, anon_client):
        """In X-Forwarded mode, anonymous users can view the index page (empty user context)."""
        r = anon_client.get("/", follow_redirects=False)
        assert r.status_code == 200

    def test_approve_returns_403_for_anon(self, anon_client):
        """Anonymous user is not admin → 403 on approve."""
        r = anon_client.post(
            f"/approve/{CLUSTER}/{REQ_NAME}",
            json={},
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 403

    def test_deny_returns_403_for_anon(self, anon_client):
        """Anonymous user is not admin → 403 on deny."""
        r = anon_client.post(
            f"/deny/{CLUSTER}/{REQ_NAME}",
            json={},
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 403

    def test_revoke_returns_403_for_anon(self, anon_client):
        """Anonymous user is not admin → 403 on revoke."""
        r = anon_client.post(
            f"/revoke/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 403

    def test_cancel_returns_401_for_anon(self, anon_client):
        """Cancel checks caller identity and returns 401 when no email present."""
        r = anon_client.post(
            f"/cancel/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 401
        assert r.headers["content-type"].startswith("application/json")

    def test_healthz_is_public(self, anon_client):
        r = anon_client.get("/healthz")
        assert r.status_code == 200
        assert "status" in r.json()

    def test_admin_page_forbidden_for_anon(self, anon_client):
        """Admin page requires admin email → 403 for anon."""
        r = anon_client.get("/admin")
        assert r.status_code == 403


class TestAdminGating:
    """Regular users must be denied access to admin-only routes."""

    def test_admin_page_forbidden_for_user(self, user_client):
        r = user_client.get("/admin")
        assert r.status_code == 403

    def test_approve_forbidden_for_user(self, user_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending"))
        r = user_client.post(f"/approve/{CLUSTER}/{REQ_NAME}", json={})
        assert r.status_code == 403

    def test_deny_forbidden_for_user(self, user_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending"))
        r = user_client.post(f"/deny/{CLUSTER}/{REQ_NAME}", json={})
        assert r.status_code == 403

    def test_revoke_forbidden_for_user(self, user_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Active"))
        r = user_client.post(
            f"/revoke/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 403


class TestAdminAccess:
    """Admin users can access admin routes."""

    def test_healthz_always_200(self, admin_client):
        r = admin_client.get("/healthz")
        assert r.status_code == 200

    def test_api_requests_count(self, admin_client):
        r = admin_client.get("/api/requests/count")
        assert r.status_code == 200
        assert "count" in r.json()

    def test_api_requests_list(self, admin_client):
        r = admin_client.get("/api/requests")
        assert r.status_code == 200
        assert "requests" in r.json()
