"""
Tests for terminal-related API endpoints:
  GET /api/terminal/{cluster}/{name}/pods
  GET /api/terminal/{cluster}/{name}/{pod}/logs

All k8s calls are mocked via conftest fixtures + monkeypatch.
"""
from unittest.mock import MagicMock
from .conftest import CLUSTER, REQ_NAME


_POD_NAME = "my-pod-abc123"


def _mock_token_client(monkeypatch, pods=None, *, access_active=True):
    """Patch _token_client to return a fake core_v1 client (or None when inactive)."""
    import main
    if not access_active:
        monkeypatch.setattr(main, "_token_client", lambda *a, **k: (None, ""))
        return

    core_v1 = MagicMock()
    pod_mock = MagicMock()
    pod_mock.metadata.name = _POD_NAME
    pod_mock.status.phase = "Running"
    pod_mock.spec.containers = [MagicMock(image="ubuntu:22.04")]
    core_v1.list_namespaced_pod.return_value.items = pods if pods is not None else [pod_mock]
    monkeypatch.setattr(main, "_token_client", lambda *a, **k: (core_v1, "default"))
    return core_v1


# ---------------------------------------------------------------------------
# GET /api/terminal/{cluster}/{name}/pods
# ---------------------------------------------------------------------------
class TestListPods:

    def test_returns_pod_list(self, admin_client, monkeypatch):
        _mock_token_client(monkeypatch)
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.status_code == 200
        data = r.json()
        assert data["error"] is None
        assert len(data["pods"]) == 1
        assert data["pods"][0]["name"] == _POD_NAME
        assert data["pods"][0]["status"] == "Running"
        assert data["pods"][0]["hasShell"] is True

    def test_inactive_access_returns_error(self, admin_client, monkeypatch):
        _mock_token_client(monkeypatch, access_active=False)
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.status_code == 200  # error is in body, not HTTP status
        assert r.json()["error"] is not None
        assert r.json()["pods"] == []

    def test_invalid_cluster_returns_400(self, admin_client):
        r = admin_client.get(f"/api/terminal/bad cluster!/{REQ_NAME}/pods")
        assert r.status_code == 400

    def test_invalid_name_returns_400(self, admin_client):
        r = admin_client.get(f"/api/terminal/{CLUSTER}/BAD_NAME/pods")
        assert r.status_code == 400

    def test_empty_pod_list(self, admin_client, monkeypatch):
        _mock_token_client(monkeypatch, pods=[])
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.status_code == 200
        assert r.json()["pods"] == []

    def test_distroless_image_has_no_shell(self, admin_client, monkeypatch):
        import main
        core_v1 = MagicMock()
        pod_mock = MagicMock()
        pod_mock.metadata.name = "distroless-pod"
        pod_mock.status.phase = "Running"
        pod_mock.spec.containers = [MagicMock(image="gcr.io/distroless/base:latest")]
        core_v1.list_namespaced_pod.return_value.items = [pod_mock]
        monkeypatch.setattr(main, "_token_client", lambda *a, **k: (core_v1, "default"))

        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.status_code == 200
        assert r.json()["pods"][0]["hasShell"] is False


# ---------------------------------------------------------------------------
# GET /api/terminal/{cluster}/{name}/{pod}/logs
# ---------------------------------------------------------------------------
class TestPodLogs:

    def test_returns_logs(self, admin_client, monkeypatch):
        import main
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod_log.return_value = "line1\nline2\n"
        monkeypatch.setattr(main, "_token_client", lambda *a, **k: (core_v1, "default"))

        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 200
        assert "line1" in r.json()["logs"]

    def test_inactive_access_returns_error(self, admin_client, monkeypatch):
        _mock_token_client(monkeypatch, access_active=False)
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 200
        assert r.json()["error"] is not None

    def test_invalid_cluster_returns_400(self, admin_client):
        r = admin_client.get(f"/api/terminal/bad!/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 400
