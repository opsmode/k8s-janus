"""
Unit tests for input validation helpers in main.py.
No mocking needed — pure regex functions.
"""
import sys, os
_WEBUI_DIR = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _WEBUI_DIR)
os.environ.setdefault("APP_DIR", _WEBUI_DIR)

import pytest
from unittest.mock import MagicMock, patch

# Patch heavy imports before loading main
with patch.dict("sys.modules", {
    "kubernetes": MagicMock(),
    "kubernetes.client": MagicMock(),
    "kubernetes.client.rest": MagicMock(),
    "kubernetes.config": MagicMock(),
    "authlib": MagicMock(),
    "authlib.integrations": MagicMock(),
    "authlib.integrations.starlette_client": MagicMock(),
    "k8s": MagicMock(),
    "terminal_ws": MagicMock(),
    "db": MagicMock(db_enabled=False, init_db=MagicMock()),
}):
    import importlib
    import main as _main_module

from main import _valid_name, _valid_cluster, _valid_ns


class TestValidName:
    def test_simple_valid(self):
        assert _valid_name("janus-req-abc123") is True

    def test_single_char(self):
        assert _valid_name("a") is True

    def test_max_length(self):
        assert _valid_name("a" + "b" * 252) is True

    def test_too_long(self):
        assert _valid_name("a" * 254) is False

    def test_empty(self):
        assert _valid_name("") is False

    def test_none(self):
        assert _valid_name(None) is False

    def test_uppercase_rejected(self):
        assert _valid_name("MyRequest") is False

    def test_slash_rejected(self):
        assert _valid_name("req/123") is False

    def test_starts_with_dash(self):
        assert _valid_name("-req") is False

    def test_numbers_only(self):
        assert _valid_name("123abc") is True

    def test_real_janus_name(self):
        assert _valid_name("janus-k-alhasan-0308012659") is True


class TestValidCluster:
    def test_simple_name(self):
        assert _valid_cluster("central") is True

    def test_gke_context(self):
        # GKE context format: gke_project_region_cluster
        assert _valid_cluster("gke_janustest-1_us-central1-a_k8s-janus-demo-1") is True

    def test_with_slash(self):
        assert _valid_cluster("context/name") is True

    def test_with_colon(self):
        assert _valid_cluster("context:name") is True

    def test_empty(self):
        assert _valid_cluster("") is False

    def test_none(self):
        assert _valid_cluster(None) is False

    def test_starts_with_dash(self):
        assert _valid_cluster("-bad") is False


class TestValidNs:
    def test_simple(self):
        assert _valid_ns("default") is True

    def test_with_dash(self):
        assert _valid_ns("my-namespace") is True

    def test_with_dot(self):
        assert _valid_ns("my.namespace") is True

    def test_uppercase_rejected(self):
        assert _valid_ns("MyNS") is False

    def test_empty(self):
        assert _valid_ns("") is False

    def test_none(self):
        assert _valid_ns(None) is False

    def test_too_long(self):
        assert _valid_ns("a" * 64) is False

    def test_starts_with_dash(self):
        assert _valid_ns("-ns") is False
