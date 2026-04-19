"""
Tests for terminal-related API endpoints:
  GET /api/terminal/{cluster}/{name}/pods
  GET /api/terminal/{cluster}/{name}/{pod}/logs
  GET /api/terminal/{cluster}/{name}/{pod}/events
"""
from unittest.mock import MagicMock
from .conftest import CLUSTER, REQ_NAME


_POD_NAME = "my-pod-abc123"


def _make_pod(name=_POD_NAME, phase="Running", image="ubuntu:22.04"):
    pod = MagicMock()
    pod.metadata.name = name
    pod.status.phase = phase
    pod.spec.containers = [MagicMock(image=image)]
    return pod


def _mock_token_client(monkeypatch, pods=None, *, access_active=True):
    """Patch _token_client to return a fake core_v1 client (or None when inactive)."""
    import routers.terminal
    if not access_active:
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (None, ""))
        return None

    core_v1 = MagicMock()
    core_v1.list_namespaced_pod.return_value.items = (
        pods if pods is not None else [_make_pod()]
    )
    monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "default"))
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
        _mock_token_client(monkeypatch, pods=[_make_pod(image="gcr.io/distroless/base:latest")])
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.status_code == 200
        assert r.json()["pods"][0]["hasShell"] is False

    def test_standard_image_has_shell(self, admin_client, monkeypatch):
        _mock_token_client(monkeypatch, pods=[_make_pod(image="python:3.12-slim")])
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.json()["pods"][0]["hasShell"] is True

    def test_repeated_poll_returns_stable_response(self, admin_client, monkeypatch):
        """Polling the endpoint twice with the same pod list returns identical data.
        Ensures the API is idempotent — the frontend diff logic can rely on stable names."""
        _mock_token_client(monkeypatch)
        r1 = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        r2 = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r1.status_code == 200
        assert r1.json()["pods"] == r2.json()["pods"]

    def test_multiple_pods_returned(self, admin_client, monkeypatch):
        pods = [_make_pod("pod-a"), _make_pod("pod-b"), _make_pod("pod-c")]
        _mock_token_client(monkeypatch, pods=pods)
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.status_code == 200
        names = [p["name"] for p in r.json()["pods"]]
        assert names == ["pod-a", "pod-b", "pod-c"]

    def test_namespace_resolved_from_token_client(self, admin_client, monkeypatch):
        """_token_client resolves the namespace (from the access request, not raw query param).
        The resolved namespace is what gets passed to list_namespaced_pod."""
        import routers.terminal
        core_v1 = MagicMock()
        core_v1.list_namespaced_pod.return_value.items = []
        # _token_client returns (client, resolved_ns) — simulate resolving to "production"
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "production"))
        admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        core_v1.list_namespaced_pod.assert_called_once()
        ca = core_v1.list_namespaced_pod.call_args
        call_ns = ca[1].get("namespace") or ca[0][0]
        assert call_ns == "production"

    def test_k8s_exception_returns_error_body(self, admin_client, monkeypatch):
        import routers.terminal
        core_v1 = MagicMock()
        core_v1.list_namespaced_pod.side_effect = Exception("connection refused")
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "default"))
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/pods?namespace=default")
        assert r.status_code == 200
        assert r.json()["error"] is not None
        assert r.json()["pods"] == []


# ---------------------------------------------------------------------------
# GET /api/terminal/{cluster}/{name}/{pod}/logs
# ---------------------------------------------------------------------------
class TestPodLogs:

    def test_returns_logs(self, admin_client, monkeypatch):
        import routers.terminal
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod_log.return_value = "line1\nline2\n"
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "default"))

        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 200
        assert "line1" in r.json()["logs"]

    def test_empty_logs_returns_empty_string(self, admin_client, monkeypatch):
        import routers.terminal
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod_log.return_value = ""
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "default"))
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 200
        assert r.json()["logs"] == ""
        assert r.json()["error"] is None

    def test_inactive_access_returns_error(self, admin_client, monkeypatch):
        _mock_token_client(monkeypatch, access_active=False)
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 200
        assert r.json()["error"] is not None

    def test_invalid_cluster_returns_400(self, admin_client):
        r = admin_client.get(f"/api/terminal/bad!/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 400

    def test_invalid_name_returns_400(self, admin_client):
        r = admin_client.get(f"/api/terminal/{CLUSTER}/BAD_NAME/{_POD_NAME}/logs")
        assert r.status_code == 400

    def test_tail_clamped_to_max(self, admin_client, monkeypatch):
        """tail param > 5000 must be clamped to 5000."""
        import routers.terminal
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod_log.return_value = "log"
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "default"))
        admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/logs?tail=99999")
        _, kwargs = core_v1.read_namespaced_pod_log.call_args
        assert kwargs.get("tail_lines", 0) <= 5000

    def test_k8s_exception_returns_error_body(self, admin_client, monkeypatch):
        import routers.terminal
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod_log.side_effect = Exception("pod not found")
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "default"))
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/logs")
        assert r.status_code == 200
        assert r.json()["error"] is not None
        assert r.json()["logs"] == ""


# ---------------------------------------------------------------------------
# GET /api/terminal/{cluster}/{name}/{pod}/events
# ---------------------------------------------------------------------------
class TestPodEvents:

    def _mock_events(self, monkeypatch, events=None):
        import routers.terminal
        core_v1 = MagicMock()
        ev_mock = MagicMock()
        ev_mock.reason = "Pulled"
        ev_mock.message = "Pulled image"
        ev_mock.type = "Normal"
        ev_mock.count = 1
        ev_mock.first_timestamp = None
        ev_mock.last_timestamp = None
        ev_mock.event_time = None
        ev_mock.source.component = "kubelet"
        core_v1.list_namespaced_event.return_value.items = (
            events if events is not None else [ev_mock]
        )
        monkeypatch.setattr(routers.terminal, "_token_client", lambda *a, **k: (core_v1, "default"))
        return core_v1

    def test_returns_events(self, admin_client, monkeypatch):
        self._mock_events(monkeypatch)
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/events")
        assert r.status_code == 200
        data = r.json()
        assert data["error"] is None
        assert len(data["events"]) == 1
        assert data["events"][0]["reason"] == "Pulled"

    def test_inactive_access_returns_error(self, admin_client, monkeypatch):
        _mock_token_client(monkeypatch, access_active=False)
        r = admin_client.get(f"/api/terminal/{CLUSTER}/{REQ_NAME}/{_POD_NAME}/events")
        assert r.status_code == 200
        assert r.json()["error"] is not None

    def test_invalid_cluster_returns_400(self, admin_client):
        r = admin_client.get(f"/api/terminal/bad!/{REQ_NAME}/{_POD_NAME}/events")
        assert r.status_code == 400
