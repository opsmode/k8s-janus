"""
API route tests: approve, deny, revoke, cancel/withdraw, TTL override.

All k8s calls are mocked via conftest fixtures.
"""
from unittest.mock import MagicMock
from .conftest import CLUSTER, REQ_NAME, USER_EMAIL, fake_ar


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------
class TestApprove:

    def test_approve_pending_ok(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending"))
        patch_status = MagicMock()
        monkeypatch.setattr(main, "_patch_status", patch_status)

        r = admin_client.post(f"/approve/{CLUSTER}/{REQ_NAME}", json={})

        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["phase"] == "Approved"
        # _patch_status must be called with phase=Approved
        args = patch_status.call_args
        assert args[0][1]["phase"] == "Approved"
        assert "approvedBy" in args[0][1]
        assert "approvedAt" in args[0][1]

    def test_approve_already_approved_is_409(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Approved"))
        r = admin_client.post(f"/approve/{CLUSTER}/{REQ_NAME}", json={})
        assert r.status_code == 409

    def test_approve_not_found_is_404(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request", lambda *a, **k: None)
        r = admin_client.post(f"/approve/{CLUSTER}/{REQ_NAME}", json={})
        assert r.status_code == 404

    def test_approve_invalid_cluster_is_400(self, admin_client):
        r = admin_client.post(f"/approve/bad cluster!/{REQ_NAME}", json={})
        assert r.status_code == 400

    def test_approve_invalid_name_is_400(self, admin_client):
        r = admin_client.post(f"/approve/{CLUSTER}/BAD_NAME", json={})
        assert r.status_code == 400

    # ----- TTL override regression -----
    def test_ttl_override_calls_patch_without_content_type_kwarg(self, admin_client, monkeypatch):
        """Regression: _content_type kwarg caused ApiTypeError → HTTP 500."""
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending", ttl=3600))
        monkeypatch.setattr(main, "_patch_status", MagicMock())

        # Mock patch_cluster_custom_object and capture kwargs
        mock_patch_obj = MagicMock()
        mock_api = MagicMock()
        mock_api.patch_cluster_custom_object = mock_patch_obj
        monkeypatch.setattr(main, "get_api_clients", lambda *a: (mock_api, MagicMock()))

        r = admin_client.post(
            f"/approve/{CLUSTER}/{REQ_NAME}",
            json={"ttl_seconds": 7200},
        )
        assert r.status_code == 200

        # Verify patch_cluster_custom_object was called
        assert mock_patch_obj.called
        # Critical: _content_type must NOT be in kwargs (caused ApiTypeError)
        _, kwargs = mock_patch_obj.call_args
        assert "_content_type" not in kwargs, \
            "_content_type kwarg causes ApiTypeError in kubernetes client"

    def test_ttl_override_sets_correct_ttl(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending", ttl=3600))
        patch_status = MagicMock()
        monkeypatch.setattr(main, "_patch_status", patch_status)

        mock_api = MagicMock()
        monkeypatch.setattr(main, "get_api_clients", lambda *a: (mock_api, MagicMock()))

        admin_client.post(
            f"/approve/{CLUSTER}/{REQ_NAME}",
            json={"ttl_seconds": 7200},
        )

        # patch_cluster_custom_object body must contain the override TTL
        call_args = mock_api.patch_cluster_custom_object.call_args
        body = call_args[1].get("body") or call_args[0][4]
        assert body["spec"]["ttlSeconds"] == 7200

    def test_ttl_override_without_value_uses_original(self, admin_client, monkeypatch):
        """Empty ttl_seconds body should not call patch_cluster_custom_object."""
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending", ttl=3600))
        monkeypatch.setattr(main, "_patch_status", MagicMock())
        mock_api = MagicMock()
        monkeypatch.setattr(main, "get_api_clients", lambda *a: (mock_api, MagicMock()))

        r = admin_client.post(f"/approve/{CLUSTER}/{REQ_NAME}", json={})
        assert r.status_code == 200
        # No spec patch when no TTL override
        assert not mock_api.patch_cluster_custom_object.called


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------
class TestDeny:

    def test_deny_pending_ok(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending"))
        patch_status = MagicMock()
        monkeypatch.setattr(main, "_patch_status", patch_status)

        r = admin_client.post(
            f"/deny/{CLUSTER}/{REQ_NAME}",
            json={"denial_reason": "not needed"},
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["phase"] == "Denied"
        args = patch_status.call_args[0][1]
        assert args["phase"] == "Denied"

    def test_deny_already_denied_is_409(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Denied"))
        r = admin_client.post(f"/deny/{CLUSTER}/{REQ_NAME}", json={})
        assert r.status_code == 409

    def test_deny_not_found_is_404(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request", lambda *a, **k: None)
        r = admin_client.post(f"/deny/{CLUSTER}/{REQ_NAME}", json={})
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------
class TestRevoke:

    def test_revoke_active_returns_json(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Active"))
        monkeypatch.setattr(main, "_patch_status", MagicMock())

        r = admin_client.post(
            f"/revoke/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["phase"] == "Revoked"

    def test_revoke_active_without_accept_redirects(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Active"))
        monkeypatch.setattr(main, "_patch_status", MagicMock())

        r = admin_client.post(
            f"/revoke/{CLUSTER}/{REQ_NAME}",
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/admin"

    def test_revoke_expired_request_noop_redirect(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Expired"))
        patch_status = MagicMock()
        monkeypatch.setattr(main, "_patch_status", patch_status)

        r = admin_client.post(
            f"/revoke/{CLUSTER}/{REQ_NAME}",
            follow_redirects=False,
        )
        # Expired → no patch, just redirect
        assert r.status_code == 303
        assert not patch_status.called


# ---------------------------------------------------------------------------
# Cancel / Withdraw
# ---------------------------------------------------------------------------
class TestCancel:

    def test_cancel_pending_by_owner_ok(self, user_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending", requester=USER_EMAIL))
        monkeypatch.setattr(main, "_patch_status", MagicMock())

        r = user_client.post(
            f"/cancel/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["phase"] == "Cancelled"

    def test_cancel_active_by_owner_ok(self, user_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Active", requester=USER_EMAIL))
        monkeypatch.setattr(main, "_patch_status", MagicMock())

        r = user_client.post(
            f"/cancel/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_cancel_by_different_user_is_403(self, user_client, monkeypatch):
        import main
        # Request belongs to someone else
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending", requester="other@test.com"))
        r = user_client.post(
            f"/cancel/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 403

    def test_cancel_already_cancelled_is_409(self, user_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Cancelled", requester=USER_EMAIL))
        r = user_client.post(
            f"/cancel/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 409

    def test_cancel_not_found_is_404(self, user_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request", lambda *a, **k: None)
        r = user_client.post(
            f"/cancel/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 404

    def test_admin_can_cancel_any_request(self, admin_client, monkeypatch):
        import main
        monkeypatch.setattr(main, "get_access_request",
                            lambda *a, **k: fake_ar(phase="Pending", requester="someone@test.com"))
        monkeypatch.setattr(main, "_patch_status", MagicMock())

        r = admin_client.post(
            f"/cancel/{CLUSTER}/{REQ_NAME}",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 200
