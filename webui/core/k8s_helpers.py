"""
Kubernetes helper utilities for K8s-Janus WebUI.
"""

import re
import collections as _collections
import logging
from datetime import datetime, timezone
from enum import Enum

from core.config import (
    DISPLAY_TZ,
    MAX_REQUESTS_PER_WINDOW, RATE_LIMIT_WINDOW_SECS,
)
from k8s import (
    get_api_clients, get_clusters, get_access_request,
    read_token_secret, CRD_GROUP, CRD_VERSION,
)

logger = logging.getLogger("k8s-janus-webui")

# ---------------------------------------------------------------------------
# Phase enum
# ---------------------------------------------------------------------------


class Phase(str, Enum):
    PENDING   = "Pending"
    APPROVED  = "Approved"
    ACTIVE    = "Active"
    DENIED    = "Denied"
    EXPIRED   = "Expired"
    REVOKED   = "Revoked"
    CANCELLED = "Cancelled"
    FAILED    = "Failed"


# ---------------------------------------------------------------------------
# Path parameter validation
# ---------------------------------------------------------------------------
_NAME_RE    = re.compile(r'^[a-z0-9][a-z0-9\-]{0,252}$')
_NS_RE      = re.compile(r'^[a-z0-9][a-z0-9\-\.]{0,62}$')
# Cluster names can include underscores (e.g. GKE context names like
# gke_project_region_cluster) and are validated against known CLUSTERS only.
_CLUSTER_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.:/]{0,252}$')


def _valid_name(s: str) -> bool:
    return bool(s and _NAME_RE.match(s))


def _valid_ns(s: str) -> bool:
    return bool(s and _NS_RE.match(s))


def _valid_cluster(s: str) -> bool:
    return bool(s and _CLUSTER_RE.match(s))


# ---------------------------------------------------------------------------
# Rate limit tracker: {email: deque of submission timestamps}
# ---------------------------------------------------------------------------
_rate_buckets: dict[str, _collections.deque] = {}


def _check_rate_limit(requester: str) -> str | None:
    """Return an error string if the requester has exceeded the rate limit, else None."""
    import time as _time
    now = _time.monotonic()
    bucket = _rate_buckets.setdefault(requester, _collections.deque())
    # Evict timestamps outside the rolling window
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECS:
        bucket.popleft()
    if len(bucket) >= MAX_REQUESTS_PER_WINDOW:
        window_min = RATE_LIMIT_WINDOW_SECS // 60
        return f"Rate limit exceeded: max {MAX_REQUESTS_PER_WINDOW} requests per {window_min}min. Try again later."
    bucket.append(now)
    return None


# ---------------------------------------------------------------------------
# K8s client helpers
# ---------------------------------------------------------------------------

def _patch_status(name: str, body: dict) -> None:
    """Patch an AccessRequest CRD status on the central cluster."""
    custom_api, _ = get_api_clients(get_clusters()[0]["name"])
    custom_api.patch_cluster_custom_object_status(
        group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", name=name,
        body={"status": body},
    )


def _token_client(name: str, cluster: str, namespace: str = ""):
    """Return (core_v1_with_token, namespace) for the given AccessRequest.

    If namespace is given, uses the token secret for that specific namespace.
    Otherwise falls back to the first namespace in the spec.
    """
    from k8s import get_client_with_token
    ar = get_access_request(name, cluster)
    if not ar:
        return None, None
    if ar.get("status", {}).get("phase") != Phase.ACTIVE:
        return None, None

    # Resolve which namespace and which secret to use
    token_secrets = ar.get("status", {}).get("tokenSecrets", {})
    namespaces    = ar.get("spec", {}).get("namespaces") or []
    if not namespaces:
        ns = ar.get("spec", {}).get("namespace", "")
        namespaces = [ns] if ns else []

    if namespace and namespace in namespaces:
        resolved_ns = namespace
    elif namespaces:
        resolved_ns = namespaces[0]
    else:
        return None, None

    secret_name = token_secrets.get(resolved_ns) or ar.get("status", {}).get("tokenSecret", "")
    if not secret_name:
        return None, None
    try:
        token, server, ca = read_token_secret(secret_name)
    except Exception as e:
        logger.error(f"🔑 Failed to read token secret {secret_name}: {e}")
        return None, None
    core_v1 = get_client_with_token(cluster, token, server, ca)
    return core_v1, resolved_ns


# ---------------------------------------------------------------------------
# Timezone helper
# ---------------------------------------------------------------------------

def _to_berlin(iso_str: str) -> str:
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone(DISPLAY_TZ)
        return local_dt.strftime("%Y-%m-%d %H:%M") + " " + local_dt.strftime("%Z")
    except Exception:
        return iso_str[:19].replace("T", " ")
