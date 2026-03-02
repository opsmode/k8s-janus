"""
Kubernetes client helpers for K8s-Janus WebUI.

Handles per-cluster client construction (via kubeconfig Secret), caching,
namespace listing, and token-scoped client creation for terminal access.
"""

import os
import time
import base64
import logging
import tempfile
import atexit

from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger("k8s-janus-webui")

JANUS_NAMESPACE = os.environ.get("JANUS_NAMESPACE", "k8s-janus")
CRD_GROUP       = "k8s-janus.opsmode.io"
CRD_VERSION     = "v1alpha1"
_raw_excluded   = os.environ.get("EXCLUDED_NAMESPACES", "")
EXCLUDED_NAMESPACES = set(n.strip() for n in _raw_excluded.split(",") if n.strip())

import json as _json

# CLUSTERS_STATIC: seed list from env (always has the central cluster at index 0).
# Remote clusters are discovered dynamically from labeled kubeconfig Secrets.
_STATIC_RAW = os.environ.get("CLUSTERS", "")
if _STATIC_RAW:
    import sys as _sys
    try:
        _static = _json.loads(_STATIC_RAW)
        if not _static:
            raise ValueError("CLUSTERS list is empty")
    except Exception as _err:
        logging.getLogger("k8s-janus-webui").critical(
            f"💥 Failed to parse CLUSTERS env var: {_err} — cannot start"
        )
        _sys.exit(1)
    CLUSTERS_STATIC: list[dict] = _static
else:
    CLUSTERS_STATIC = []

_MANAGED_LABEL = "k8s-janus.opsmode.io/managed"
_KUBECONFIG_SUFFIX = "-kubeconfig"


def _discover_clusters() -> list[dict]:
    """
    Build the live CLUSTERS list:
    1. Central cluster is always first (from CLUSTERS_STATIC[0] or a synthetic entry).
    2. Remote clusters are discovered by scanning kubeconfig Secrets labeled
       ``k8s-janus.opsmode.io/managed=true`` in JANUS_NAMESPACE.
    """
    try:
        core_v1 = _get_central_core_v1()
        secrets = core_v1.list_namespaced_secret(
            namespace=JANUS_NAMESPACE,
            label_selector=f"{_MANAGED_LABEL}=true",
        )
    except Exception as e:
        logger.warning(f"_discover_clusters: could not list secrets: {e}")
        # Fallback: return static list
        if CLUSTERS_STATIC:
            return list(CLUSTERS_STATIC)
        return [{"name": "local", "displayName": "Local"}]

    remotes: list[dict] = []
    for s in secrets.items:
        name = s.metadata.name or ""
        if not name.endswith(_KUBECONFIG_SUFFIX):
            continue
        cluster_name = name[: -len(_KUBECONFIG_SUFFIX)]
        # Prefer display name from secret annotations if present
        display_name = (s.metadata.annotations or {}).get(
            "k8s-janus.opsmode.io/displayName", cluster_name
        )
        remotes.append({"name": cluster_name, "displayName": display_name, "secretName": name})

    # Sort remotes by name for stable ordering
    remotes.sort(key=lambda c: c["name"])

    if CLUSTERS_STATIC:
        central = dict(CLUSTERS_STATIC[0])
    else:
        central = {"name": "local", "displayName": "Local"}

    return [central] + remotes


# Module-level CLUSTERS — refreshed on each request via get_clusters()
# but kept as a simple cached variable with short TTL to avoid hammering the API.
_clusters_cache: dict = {"clusters": None, "expires": 0.0}
_CLUSTERS_TTL = 30.0  # seconds


def get_clusters() -> list[dict]:
    """Return the live cluster list, refreshed every 30 s."""
    now = time.monotonic()
    if _clusters_cache["clusters"] is not None and now < _clusters_cache["expires"]:
        return _clusters_cache["clusters"]
    result = _discover_clusters()
    _clusters_cache["clusters"] = result
    _clusters_cache["expires"] = now + _CLUSTERS_TTL
    return result


def invalidate_clusters_cache() -> None:
    """Force a refresh on the next get_clusters() call."""
    _clusters_cache["expires"] = 0.0


# Backwards-compat alias used by main.py imports — returns live list
@property  # type: ignore[misc]
def _clusters_property():
    return get_clusters()


# Eagerly populate on first import
CLUSTERS: list[dict] = get_clusters()

# ---------------------------------------------------------------------------
# Temp file tracker — cleaned up at process exit
# ---------------------------------------------------------------------------
_tmp_files: list[str] = []


def _register_tmp(path: str) -> str:
    _tmp_files.append(path)
    return path


@atexit.register
def _cleanup_tmp_files():
    for path in _tmp_files:
        try:
            os.unlink(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Client cache
# ---------------------------------------------------------------------------
_CLIENT_CACHE: dict[str, tuple] = {}
_CLIENT_TTL = 3600  # seconds — kubeconfig Secrets rarely change


def get_cluster_config(cluster_name: str) -> dict | None:
    for c in get_clusters():
        if c["name"] == cluster_name:
            return c
    return None


def _get_central_core_v1() -> client.CoreV1Api:
    """Return a CoreV1Api for the central (local) cluster."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def _build_api_clients(cluster_cfg: dict) -> tuple:
    """Build (CustomObjectsApi, CoreV1Api) for a cluster.

    Central cluster (CLUSTERS[0]): uses in-cluster config so the webui's own
    ServiceAccount (janus-webui) is used — it has CRD + namespace permissions.

    Remote clusters: load the static kubeconfig from the cluster's Secret,
    which authenticates as janus-remote SA on that cluster.
    """
    if cluster_cfg["name"] == get_clusters()[0]["name"]:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        return client.CustomObjectsApi(api_client=api_client), client.CoreV1Api(api_client=api_client)

    secret_name = cluster_cfg.get("secretName") or f"{cluster_cfg['name']}-kubeconfig"

    core_v1_central = _get_central_core_v1()
    secret = core_v1_central.read_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE)
    kubeconfig_bytes = base64.b64decode(secret.data["kubeconfig"])

    with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as f:
        _register_tmp(f.name)
        f.write(kubeconfig_bytes)
        kubeconfig_path = f.name

    remote_cfg = client.Configuration()
    config.load_kube_config(config_file=kubeconfig_path, client_configuration=remote_cfg)
    api_client = client.ApiClient(configuration=remote_cfg)
    return client.CustomObjectsApi(api_client=api_client), client.CoreV1Api(api_client=api_client)


def get_api_clients(cluster_name: str) -> tuple:
    """Return (CustomObjectsApi, CoreV1Api) for the given cluster, with caching."""
    cluster_cfg = get_cluster_config(cluster_name)
    if not cluster_cfg:
        # Refresh cache and retry once — new cluster may have just been set up
        invalidate_clusters_cache()
        cluster_cfg = get_cluster_config(cluster_name)
    if not cluster_cfg:
        logger.error(f"❌ Unknown cluster: {cluster_name}")
        raise ValueError(f"Unknown cluster: {cluster_name}")

    cached = _CLIENT_CACHE.get(cluster_name)
    if cached:
        custom_api, core_v1, expires_ts = cached
        if time.monotonic() < expires_ts:
            return custom_api, core_v1

    logger.info(f"🔧 Building client for cluster: {cluster_name}")
    apis = _build_api_clients(cluster_cfg)
    _CLIENT_CACHE[cluster_name] = (*apis, time.monotonic() + _CLIENT_TTL)
    return apis


def get_client_with_token(cluster: str, token: str, server: str, ca_pem: str):
    """Create a CoreV1Api client scoped to a temporary token."""
    configuration = client.Configuration()
    configuration.host = server
    configuration.api_key = {"authorization": f"Bearer {token}"}
    configuration.verify_ssl = True
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.crt') as f:
        _register_tmp(f.name)
        f.write(ca_pem)
        configuration.ssl_ca_cert = f.name
    return client.CoreV1Api(client.ApiClient(configuration))


def get_allowed_namespaces(cluster_name: str) -> list[str]:
    logger.info(f"🔍 Fetching namespaces for cluster: {cluster_name}")
    try:
        _, core_v1 = get_api_clients(cluster_name)
        ns_list = core_v1.list_namespace()
        namespaces = sorted([
            ns.metadata.name
            for ns in ns_list.items
            if ns.metadata.name not in EXCLUDED_NAMESPACES
        ])
        logger.info(f"✅ Found {len(namespaces)} accessible namespaces in cluster {cluster_name}")
        return namespaces
    except Exception as e:
        logger.error(f"💥 Failed to fetch namespaces for cluster {cluster_name}: {e}")
        return []


def get_access_request(name: str, cluster_name: str) -> dict | None:
    custom_api, _ = get_api_clients(get_clusters()[0]["name"])
    try:
        return custom_api.get_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", name=name,
        )
    except ApiException as e:
        if e.status == 404:
            return None
        raise


def list_access_requests() -> list:
    all_requests = []
    clusters = get_clusters()
    try:
        custom_api, _ = get_api_clients(clusters[0]["name"])
        result = custom_api.list_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests",
        )
        for item in result.get("items", []):
            target_cluster = item.get("spec", {}).get("cluster", clusters[0]["name"])
            cluster_cfg = get_cluster_config(target_cluster)
            item["_cluster"] = target_cluster
            item["_clusterDisplay"] = cluster_cfg.get("displayName", target_cluster) if cluster_cfg else target_cluster
            all_requests.append(item)
    except Exception as e:
        logger.error(f"💥 Failed to list access requests: {e}")

    return sorted(
        all_requests,
        key=lambda x: x.get("metadata", {}).get("creationTimestamp", ""),
        reverse=True,
    )


def read_token_secret(secret_name: str) -> tuple[str, str, str]:
    """Return (token, server, ca_pem) from a k8s-janus token secret."""
    import base64 as b64
    _, core_v1 = get_api_clients(get_clusters()[0]["name"])
    secret = core_v1.read_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE)
    token  = b64.b64decode(secret.data.get("token",  "")).decode("utf-8")
    server = b64.b64decode(secret.data.get("server", "")).decode("utf-8")
    # ca is stored as base64(base64(PEM)) by the controller:
    #   K8s Secret envelope → outer b64decode → inner b64decode → raw PEM
    ca_outer = b64.b64decode(secret.data.get("ca", ""))
    try:
        ca = b64.b64decode(ca_outer).decode("utf-8")
    except Exception:
        # Fallback: already raw PEM after single decode
        ca = ca_outer.decode("utf-8")
    return token, server, ca
