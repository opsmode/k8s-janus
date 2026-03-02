import os
import base64
import logging
import asyncio
import json
import tempfile
import yaml
from datetime import datetime, timezone, timedelta

import kopf
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from db import init_db, upsert_request, log_audit, _now

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
JANUS_NAMESPACE = os.environ.get("JANUS_NAMESPACE", "k8s-janus")
MAX_TTL_SECONDS = int(os.environ.get("MAX_TTL_SECONDS", "28800"))
MIN_TTL_SECONDS = 600
CRD_GROUP = "k8s-janus.opsmode.io"
_STATIC_RAW = os.environ.get("CLUSTERS", "")
if _STATIC_RAW:
    try:
        _CLUSTERS_STATIC: list[dict] = json.loads(_STATIC_RAW)
        if not _CLUSTERS_STATIC:
            raise ValueError("CLUSTERS list is empty")
    except Exception as _clusters_err:
        import sys
        logging.basicConfig()
        logging.getLogger(__name__).critical(
            f"💥 Failed to parse CLUSTERS env var: {_clusters_err} — cannot start"
        )
        sys.exit(1)
else:
    _CLUSTERS_STATIC = []

_MANAGED_LABEL = "k8s-janus.opsmode.io/managed"
_KUBECONFIG_SUFFIX = "-kubeconfig"
import time as _time
_clusters_cache: dict = {"clusters": None, "expires": 0.0}
_CLUSTERS_TTL = 30.0


def _get_central_core_v1_ctrl():
    """Return CoreV1Api using in-cluster config for the controller SA."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def get_clusters() -> list[dict]:
    """Return live cluster list: central + remotes discovered from labeled secrets."""
    now = _time.monotonic()
    if _clusters_cache["clusters"] is not None and now < _clusters_cache["expires"]:
        return _clusters_cache["clusters"]

    try:
        core_v1 = _get_central_core_v1_ctrl()
        secrets = core_v1.list_namespaced_secret(
            namespace=JANUS_NAMESPACE,
            label_selector=f"{_MANAGED_LABEL}=true",
        )
        remotes: list[dict] = []
        for s in secrets.items:
            name = s.metadata.name or ""
            if not name.endswith(_KUBECONFIG_SUFFIX):
                continue
            cluster_name = name[: -len(_KUBECONFIG_SUFFIX)]
            display_name = (s.metadata.annotations or {}).get(
                "k8s-janus.opsmode.io/displayName", cluster_name
            )
            remotes.append({"name": cluster_name, "displayName": display_name, "secretName": name})
        remotes.sort(key=lambda c: c["name"])
    except Exception as e:
        logging.getLogger(__name__).warning(f"get_clusters: could not list secrets: {e}")
        remotes = []

    if _CLUSTERS_STATIC:
        central = dict(_CLUSTERS_STATIC[0])
    else:
        central = {"name": "local", "displayName": "Local"}

    result = [central] + remotes
    _clusters_cache["clusters"] = result
    _clusters_cache["expires"] = now + _CLUSTERS_TTL
    return result


# Module-level alias for compatibility
CLUSTERS: list[dict] = get_clusters()

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("k8s-janus-audit")


class _HealthzFilter(logging.Filter):
    def filter(self, record):
        return "GET /healthz" not in record.getMessage()


logging.getLogger("aiohttp.access").addFilter(_HealthzFilter())


SEP = "⚡" * 30


def audit(event: str, name: str, **kwargs):
    """Emit a structured audit log line."""
    audit_logger.info(json.dumps({
        "audit": True,
        "event": event,
        "request": name,
        "ts": datetime.now(timezone.utc).isoformat(),
        **kwargs,
    }))


# ---------------------------------------------------------------------------
# Kubernetes client helpers
# ---------------------------------------------------------------------------


def get_k8s_clients():
    """Return (CoreV1Api, RbacAuthorizationV1Api) for the central (local) cluster."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api(), client.RbacAuthorizationV1Api()


def get_k8s_clients_for_cluster(cluster_name: str):
    """Return (CoreV1Api, RbacAuthorizationV1Api) for any cluster.

    Central cluster (CLUSTERS[0]): uses in-cluster config so the controller's
    own ServiceAccount (janus-controller) is used — it has full CRD + RBAC
    permissions on the central cluster.

    Remote clusters: load the static kubeconfig from the cluster's Secret,
    which authenticates as janus-remote SA on that cluster.
    """
    clusters = get_clusters()
    cluster_cfg = next((c for c in clusters if c["name"] == cluster_name), None)
    if not cluster_cfg:
        raise ValueError(f"Unknown cluster: {cluster_name}")

    if cluster_name == clusters[0]["name"]:
        return get_k8s_clients()

    secret_name = cluster_cfg.get("secretName") or f"{cluster_name}-kubeconfig"

    core_v1_central, _ = get_k8s_clients()
    secret = core_v1_central.read_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE)
    kubeconfig_bytes = base64.b64decode(secret.data["kubeconfig"])

    with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as f:
        f.write(kubeconfig_bytes)
        kubeconfig_path = f.name

    try:
        remote_cfg = client.Configuration()
        config.load_kube_config(config_file=kubeconfig_path, client_configuration=remote_cfg)
        api_client = client.ApiClient(configuration=remote_cfg)
        return client.CoreV1Api(api_client=api_client), client.RbacAuthorizationV1Api(api_client=api_client)
    finally:
        try:
            os.unlink(kubeconfig_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# kopf handlers
# ---------------------------------------------------------------------------

@kopf.on.create("k8s-janus.opsmode.io", "v1alpha1", "accessrequests")
async def on_create(name, spec, status, patch, **kwargs):
    """New AccessRequest created — validate and notify approvers."""
    requester = spec.get("requester", "unknown")
    cluster = spec.get("cluster", get_clusters()[0]["name"])
    namespace = spec.get("namespace", "unknown")
    logger.info(SEP)
    logger.info(f"📥 New AccessRequest [{name}] from {requester} → cluster={cluster} ns={namespace}")

    # If phase is already set (controller restarted and re-fired on_create),
    # skip to avoid sending duplicate notifications.
    if status.get("phase"):
        logger.info(f"⏭️  [{name}] already has phase={status.get('phase')}, skipping re-notification")
        return

    ttl = spec.get("ttlSeconds", 3600)
    if ttl > MAX_TTL_SECONDS:
        logger.warning(f"⛔ [{name}] TTL {ttl}s exceeds maximum {MAX_TTL_SECONDS}s — auto-denying")
        patch.status["phase"] = "Denied"
        patch.status["message"] = f"Requested TTL {ttl}s exceeds maximum {MAX_TTL_SECONDS}s"
        return
    if ttl < MIN_TTL_SECONDS:
        logger.warning(f"⛔ [{name}] TTL {ttl}s is below minimum {MIN_TTL_SECONDS}s — auto-denying")
        patch.status["phase"] = "Denied"
        patch.status["message"] = f"Requested TTL {ttl}s is below minimum {MIN_TTL_SECONDS}s"
        return

    patch.status["phase"] = "Pending"
    patch.status["message"] = "Waiting for DevOps approval"

    audit("request.created", name, requester=requester, cluster=cluster, namespace=namespace, ttl=ttl)

    created_ts = kwargs.get("meta", {}).get("creationTimestamp", "")
    try:
        created_at = datetime.fromisoformat(created_ts.replace("Z", "+00:00")) if created_ts else _now()
    except Exception:
        created_at = _now()
    upsert_request(
        name,
        cluster=cluster,
        namespace=namespace,
        requester=requester,
        ttl_seconds=ttl,
        reason=spec.get("reason", ""),
        phase="Pending",
        created_at=created_at,
    )
    log_audit(name, "request.created", actor=requester, detail=f"cluster={cluster} ns={namespace} ttl={ttl}s")


@kopf.on.field("k8s-janus.opsmode.io", "v1alpha1", "accessrequests", field="status.phase")
async def on_phase_change(name, spec, status, old, new, patch, **kwargs):
    """React when phase transitions to Approved, Denied, or Revoked."""
    cluster = spec.get("cluster", get_clusters()[0]["name"])
    namespace = spec.get("namespace", "unknown")
    requester = spec.get("requester", "unknown")
    logger.info(SEP)
    logger.info(f"🔄 [{name}] phase transition: {old} → {new}  (cluster={cluster} ns={namespace})")

    if new == "Approved":
        # Guard against duplicate grant on kopf retry — check if already Active
        if status.get("tokenSecret"):
            logger.info(f"⏭️  [{name}] already has tokenSecret, skipping duplicate grant")
            return
        await grant_access(name, spec, patch)
    elif new == "Denied":
        approver = status.get("approvedBy", "unknown")
        audit("request.denied", name, requester=requester, cluster=cluster, namespace=namespace, approver=approver)
        logger.info(f"❌ [{name}] denied by {approver} (cluster={cluster} ns={namespace})")
        upsert_request(name, phase="Denied", approved_by=approver, denied_at=_now(),
                       cluster=cluster, namespace=namespace, requester=requester,
                       ttl_seconds=spec.get("ttlSeconds", 3600),
                       denial_reason=status.get("denialReason", ""),
                       created_at=_now())
        log_audit(name, "request.denied", actor=approver,
                  detail=status.get("denialReason", "") or f"denied by {approver}")
    elif new == "Revoked":
        approver = status.get("approvedBy", "unknown")
        audit("access.revoked", name, requester=requester, cluster=cluster, namespace=namespace)
        logger.info(f"🚫 [{name}] revoked by admin — triggering immediate cleanup on cluster={cluster} ns={namespace}")
        upsert_request(name, phase="Revoked", approved_by=approver, revoked_at=_now(),
                       cluster=cluster, namespace=namespace, requester=requester,
                       ttl_seconds=spec.get("ttlSeconds", 3600), created_at=_now())
        log_audit(name, "access.revoked", actor=approver, detail=f"cluster={cluster} ns={namespace}")
        await cleanup_access(name, namespace, revoked=True, target_cluster=cluster)


async def grant_access(name: str, spec: dict, patch):
    """Create SA + RoleBinding + TokenRequest on target cluster, store token in Secret on central cluster."""
    target_cluster = spec.get("cluster", get_clusters()[0]["name"])
    requester = spec.get("requester", "unknown")
    namespace = spec.get("namespace", "default")
    logger.info(SEP)

    logger.info(f"🔑 [{name}] granting access for {requester} on cluster={target_cluster} ns={namespace}")

    try:
        core_v1_remote, rbac_v1_remote = get_k8s_clients_for_cluster(target_cluster)
        logger.info(f"🌐 [{name}] connected to cluster={target_cluster}")
    except ValueError as e:
        logger.error(f"💥 [{name}] unknown cluster '{target_cluster}': {e}")
        # Keep current phase (likely "Approved"), just set error message
        patch.status["message"] = f"❌ Error: Unknown cluster: {target_cluster}"
        audit("access.failed", name, requester=spec.get("requester", "unknown"), cluster=target_cluster, error=str(e))
        return
    except Exception as e:
        logger.error(f"💥 [{name}] failed to connect to cluster={target_cluster}: {e}")
        # Keep current phase, set error message
        patch.status["message"] = f"❌ Error: Could not connect to cluster {target_cluster}: {e}"
        return

    try:
        ttl = int(spec.get("ttlSeconds", 3600))
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()

        sa_name = name
        rb_name = name
        secret_name = f"janus-token-{name}"

        labels = {
            "k8s-janus.opsmode.io/request": name,
            "k8s-janus.opsmode.io/requester": requester.replace("@", "_at_").replace(".", "-")[:63],
        }
        annotations = {"k8s-janus.opsmode.io/expires-at": expires_at}

        # 1. Create ServiceAccount on target cluster
        sa = client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(name=sa_name, namespace=namespace, labels=labels, annotations=annotations)
        )
        try:
            core_v1_remote.create_namespaced_service_account(namespace=namespace, body=sa)
            logger.info(f"👤 [{name}] created ServiceAccount={sa_name} in cluster={target_cluster} ns={namespace}")
        except ApiException as e:
            if e.status != 409:
                raise
            logger.info(f"👤 [{name}] ServiceAccount={sa_name} already exists in cluster={target_cluster} ns={namespace}")

        # 2. Create RoleBinding on target cluster
        rb = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(name=rb_name, namespace=namespace, labels=labels, annotations=annotations),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="ClusterRole",
                name="janus-pod-exec",
            ),
            subjects=[client.RbacV1Subject(kind="ServiceAccount", name=sa_name, namespace=namespace)]
        )
        try:
            rbac_v1_remote.create_namespaced_role_binding(namespace=namespace, body=rb)
            logger.info(f"🔗 [{name}] created RoleBinding={rb_name} in cluster={target_cluster} ns={namespace}")
        except ApiException as e:
            if e.status != 409:
                raise
            logger.info(f"🔗 [{name}] RoleBinding={rb_name} already exists in cluster={target_cluster} ns={namespace}")

        # 3. Resolve server URL and CA for the target cluster.
        #    Central cluster: read from the in-cluster service account files.
        #    Remote clusters: parse from the kubeconfig Secret.
        _clusters_live = get_clusters()
        cluster_cfg = next((c for c in _clusters_live if c["name"] == target_cluster), None)
        server_url = ""
        ca_data = ""

        try:
            if target_cluster == _clusters_live[0]["name"]:
                # In-cluster: host is injected as KUBERNETES_SERVICE_HOST/PORT
                host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
                port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
                server_url = f"https://{host}:{port}"
                ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
                if os.path.exists(ca_path):
                    with open(ca_path, "rb") as f:
                        ca_data = base64.b64encode(f.read()).decode()
                logger.info(f"🗺️  [{name}] resolved server URL for central cluster: {server_url}")
            else:
                secret_name_cfg = cluster_cfg.get("secretName") or f"{target_cluster}-kubeconfig"
                if secret_name_cfg:
                    core_v1_central, _ = get_k8s_clients()
                    kc_secret = core_v1_central.read_namespaced_secret(name=secret_name_cfg, namespace=JANUS_NAMESPACE)
                    kubeconfig_raw = base64.b64decode(kc_secret.data["kubeconfig"])
                    kc = yaml.safe_load(kubeconfig_raw)
                    cluster_entry = kc.get("clusters", [{}])[0].get("cluster", {})
                    server_url = cluster_entry.get("server", "")
                    ca_b64 = cluster_entry.get("certificate-authority-data", "")
                    ca_data = ca_b64  # already base64-encoded
                    logger.info(f"🗺️  [{name}] resolved server URL for cluster={target_cluster}: {server_url}")
        except Exception as e:
            logger.warning(f"⚠️  [{name}] could not resolve server/CA for cluster={target_cluster}: {e}")

        # 4. Issue TokenRequest on the remote cluster.
        #    Use audiences=[] so GKE defaults to the cluster's own OIDC issuer URL,
        #    which is the only audience each GKE cluster accepts for SA tokens.
        token_request = client.AuthenticationV1TokenRequest(
            spec=client.V1TokenRequestSpec(audiences=[], expiration_seconds=ttl)
        )
        tr = core_v1_remote.create_namespaced_service_account_token(
            name=sa_name, namespace=namespace, body=token_request
        )
        token = tr.status.token
        logger.info(f"🎟️  [{name}] issued token for SA={sa_name} in cluster={target_cluster}, ttl={ttl}s, expires={expires_at}")

        # 5. Store token + connection info in Secret on central cluster
        import base64 as b64
        core_v1_central, _ = get_k8s_clients()
        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace=JANUS_NAMESPACE,
                labels=labels,
                annotations=annotations,
            ),
            data={
                "token": b64.b64encode(token.encode()).decode(),
                "server": b64.b64encode(server_url.encode()).decode(),
                "ca": ca_data if ca_data else "",
                "namespace": b64.b64encode(namespace.encode()).decode(),
            }
        )
        try:
            core_v1_central.create_namespaced_secret(namespace=JANUS_NAMESPACE, body=secret)
            logger.info(f"🔐 [{name}] stored token Secret={secret_name} in ns={JANUS_NAMESPACE}")
        except ApiException as e:
            if e.status == 409:
                core_v1_central.replace_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE, body=secret)
                logger.info(f"🔐 [{name}] replaced existing token Secret={secret_name} in ns={JANUS_NAMESPACE}")

        patch.status["serviceAccount"] = sa_name
        patch.status["tokenSecret"] = secret_name
        patch.status["expiresAt"] = expires_at
        patch.status["phase"] = "Active"
        patch.status["message"] = f"Access granted until {expires_at}"

        audit("access.granted", name, requester=requester, cluster=target_cluster, namespace=namespace, expires_at=expires_at)
        logger.info(f"✅ [{name}] access GRANTED — requester={requester} cluster={target_cluster} ns={namespace} expires={expires_at}")

        try:
            expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            expires_dt = None
        upsert_request(
            name,
            phase="Active",
            cluster=target_cluster,
            namespace=namespace,
            requester=requester,
            ttl_seconds=ttl,
            reason=spec.get("reason", ""),
            approved_by=spec.get("approvedBy", ""),
            service_account=sa_name,
            token_secret=secret_name,
            active_at=_now(),
            expires_at=expires_dt,
            created_at=_now(),
        )
        log_audit(name, "access.granted", actor=requester,
                  detail=f"cluster={target_cluster} ns={namespace} expires={expires_at}")

        asyncio.create_task(cleanup_after_ttl(name, namespace, ttl, target_cluster))

    except Exception as e:
        logger.error(f"💥 [{name}] FAILED to grant access on cluster={target_cluster} ns={namespace}: {type(e).__name__}: {e}")
        patch.status["phase"] = "Failed"
        patch.status["message"] = "❌ Access grant failed — check controller logs"
        audit("access.failed", name, requester=requester, cluster=target_cluster, error=str(e))


async def cleanup_after_ttl(request_name: str, namespace: str, ttl: int, target_cluster: str = ""):
    logger.info(f"⏳ [{request_name}] TTL cleanup scheduled in {ttl}s for cluster={target_cluster} ns={namespace}")
    await asyncio.sleep(ttl)
    await cleanup_access(request_name, namespace, target_cluster=target_cluster)


async def cleanup_access(request_name: str, namespace: str, revoked: bool = False, target_cluster: str = ""):
    """Delete SA + RoleBinding on target cluster, token Secret on central cluster, mark Expired."""
    reason = "revoked" if revoked else "TTL expired"
    logger.info(SEP)
    logger.info(f"🧹 [{request_name}] starting cleanup ({reason}) on cluster={target_cluster} ns={namespace}")

    try:
        core_v1_remote, rbac_v1_remote = get_k8s_clients_for_cluster(target_cluster) if target_cluster else (None, None)
        if core_v1_remote is None:
            core_v1_remote, rbac_v1_remote = get_k8s_clients()
    except ValueError:
        core_v1_remote, rbac_v1_remote = get_k8s_clients()

    sa_name = request_name
    rb_name = request_name
    secret_name = f"janus-token-{request_name}"

    # Delete RoleBinding on target cluster
    try:
        rbac_v1_remote.delete_namespaced_role_binding(name=rb_name, namespace=namespace)
        logger.info(f"🗑️  [{request_name}] deleted RoleBinding={rb_name} from cluster={target_cluster} ns={namespace}")
    except ApiException as e:
        if e.status == 404:
            logger.info(f"👻 [{request_name}] RoleBinding={rb_name} already gone from cluster={target_cluster} ns={namespace}")
        else:
            logger.error(f"💥 [{request_name}] error deleting RoleBinding={rb_name} from cluster={target_cluster}: {e}")

    # Delete ServiceAccount on target cluster (also invalidates token immediately)
    try:
        core_v1_remote.delete_namespaced_service_account(name=sa_name, namespace=namespace)
        logger.info(f"🗑️  [{request_name}] deleted ServiceAccount={sa_name} from cluster={target_cluster} ns={namespace}")
    except ApiException as e:
        if e.status == 404:
            logger.info(f"👻 [{request_name}] ServiceAccount={sa_name} already gone from cluster={target_cluster} ns={namespace}")
        else:
            logger.error(f"💥 [{request_name}] error deleting ServiceAccount={sa_name} from cluster={target_cluster}: {e}")

    # Delete token Secret on central cluster
    try:
        core_v1_central, _ = get_k8s_clients()
        core_v1_central.delete_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE)
        logger.info(f"🗑️  [{request_name}] deleted token Secret={secret_name} from ns={JANUS_NAMESPACE}")
    except ApiException as e:
        if e.status == 404:
            logger.info(f"👻 [{request_name}] token Secret={secret_name} already gone from ns={JANUS_NAMESPACE}")
        else:
            logger.error(f"💥 [{request_name}] error deleting Secret={secret_name}: {e}")

    if not revoked:
        try:
            core_v1_central, _ = get_k8s_clients()
            custom = client.CustomObjectsApi(api_client=core_v1_central.api_client)
            custom.patch_cluster_custom_object_status(
                group="k8s-janus.opsmode.io",
                version="v1alpha1",
                plural="accessrequests",
                name=request_name,
                body={"status": {"phase": "Expired", "message": "Access TTL expired — credentials removed"}},
            )
            audit("access.expired", request_name, namespace=namespace, cluster=target_cluster)
            logger.info(f"💀 [{request_name}] marked as Expired — all credentials removed from cluster={target_cluster} ns={namespace}")
            upsert_request(request_name, phase="Expired", expired_at=_now(),
                           cluster=target_cluster, namespace=namespace,
                           requester="", ttl_seconds=0, created_at=_now())
            log_audit(request_name, "access.expired", detail=f"cluster={target_cluster} ns={namespace}")
        except ApiException as e:
            logger.error(f"💥 [{request_name}] failed to patch AccessRequest status to Expired: {e}")


# ---------------------------------------------------------------------------
# Periodic cleanup of terminal-phase CRDs older than retention period
# ---------------------------------------------------------------------------

CLEANUP_TERMINAL_PHASES = {"Expired", "Denied", "Revoked"}
CLEANUP_RETENTION_SECONDS = int(os.environ.get("CRD_RETENTION_SECONDS", str(24 * 3600)))


async def _periodic_crd_cleanup_loop():
    """Background task: delete terminal-phase AccessRequests older than retention period."""
    await asyncio.sleep(300)  # initial delay: 5 minutes after startup
    while True:
        try:
            custom = client.CustomObjectsApi()
            result = custom.list_cluster_custom_object(
                group=CRD_GROUP, version="v1alpha1", plural="accessrequests"
            )
            now = datetime.now(timezone.utc)
            deleted = 0
            for ar in result.get("items", []):
                phase = ar.get("status", {}).get("phase", "")
                if phase not in CLEANUP_TERMINAL_PHASES:
                    continue
                ts_str = ar.get("metadata", {}).get("creationTimestamp", "")
                if not ts_str:
                    continue
                created = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                age_seconds = (now - created).total_seconds()
                if age_seconds >= CLEANUP_RETENTION_SECONDS:
                    name = ar["metadata"]["name"]
                    try:
                        custom.delete_cluster_custom_object(
                            group=CRD_GROUP, version="v1alpha1", plural="accessrequests", name=name
                        )
                        audit("crd.deleted", name, phase=phase, age_days=round(age_seconds / 86400, 1))
                        logger.info(f"🗑️  [periodic] deleted stale CRD={name} phase={phase} age={age_seconds/86400:.1f}d")
                        log_audit(name, "crd.deleted", detail=f"phase={phase} age={age_seconds/86400:.1f}d")
                        deleted += 1
                    except ApiException as e:
                        if e.status != 404:
                            logger.error(f"💥 [periodic] failed to delete CRD={name}: {e}")
            if deleted:
                logger.info(f"🧹 [periodic] cleanup done — deleted {deleted} stale terminal CRDs")
            else:
                logger.info("✨ [periodic] cleanup done — no stale CRDs found")
        except Exception as e:
            logger.error(f"💥 [periodic] CRD cleanup loop failed: {e}")
        await asyncio.sleep(3600)  # run every hour


# ---------------------------------------------------------------------------
# Startup: ensure the pod-exec ClusterRole exists
# ---------------------------------------------------------------------------

def ensure_pod_exec_clusterrole(rbac_v1, cluster_name: str):
    """Ensure janus-pod-exec ClusterRole exists — get first, create only if missing."""
    rules = [
        client.V1PolicyRule(api_groups=[""], resources=["pods/exec"], verbs=["create", "get"]),
        client.V1PolicyRule(api_groups=[""], resources=["pods"], verbs=["get", "list"]),
        client.V1PolicyRule(api_groups=[""], resources=["pods/log"], verbs=["get", "list"]),
        client.V1PolicyRule(api_groups=[""], resources=["events"], verbs=["get", "list"]),
    ]
    pod_exec_role = client.V1ClusterRole(
        metadata=client.V1ObjectMeta(
            name="janus-pod-exec",
            labels={"app.kubernetes.io/managed-by": "k8s-janus"},
        ),
        rules=rules,
    )
    # Create or replace (to pick up rule changes on existing clusters)
    try:
        rbac_v1.read_cluster_role(name="janus-pod-exec")
        rbac_v1.replace_cluster_role(name="janus-pod-exec", body=pod_exec_role)
        logger.info(f"🛡️  updated janus-pod-exec ClusterRole on cluster={cluster_name}")
    except ApiException as e:
        if e.status != 404:
            logger.warning(f"⚠️  could not update janus-pod-exec on cluster={cluster_name}: {e}")
            return
        # Doesn't exist — create it
        try:
            rbac_v1.create_cluster_role(body=pod_exec_role)
            logger.info(f"🛡️  created janus-pod-exec ClusterRole on cluster={cluster_name}")
        except ApiException as ce:
            if ce.status == 403:
                logger.warning(f"⚠️  no permission to create janus-pod-exec on cluster={cluster_name} — must be pre-created manually")
            else:
                logger.error(f"💥 failed to create janus-pod-exec on cluster={cluster_name}: {ce}")


async def _setup_remote_clusterroles():
    """Best-effort background task: ensure janus-pod-exec ClusterRole on all remote clusters."""
    _clusters_live = get_clusters()
    _, rbac_v1 = get_k8s_clients()
    ensure_pod_exec_clusterrole(rbac_v1, _clusters_live[0]["name"])
    for cluster in _clusters_live:
        cname = cluster.get("name", "")
        if not cname or cname == _clusters_live[0]["name"]:
            continue
        try:
            _, remote_rbac = get_k8s_clients_for_cluster(cname)
            ensure_pod_exec_clusterrole(remote_rbac, cname)
        except Exception as e:
            logger.error(f"💥 failed to ensure janus-pod-exec on remote cluster={cname}: {e}")


@kopf.on.startup()
async def startup(**kwargs):
    logger.info(f"🚀 k8s-janus controller starting up on cluster={get_clusters()[0]['name']}")
    init_db()
    try:
        from db import purge_old_records
        purge_old_records(days=30)
    except Exception as e:
        logger.warning(f"⚠️  Startup DB purge failed (non-fatal): {e}")

    # Fire-and-forget: don't block kopf startup (and its liveness HTTP server)
    # while connecting to remote clusters — probes would fail during slow connections
    asyncio.create_task(_setup_remote_clusterroles())

    # Reschedule TTL cleanup for any Active requests that survived a restart
    try:
        get_k8s_clients()  # ensure kube config is loaded before using client directly
        custom = client.CustomObjectsApi()
        result = custom.list_cluster_custom_object(
            group=CRD_GROUP, version="v1alpha1", plural="accessrequests"
        )
        now = datetime.now(timezone.utc)
        for ar in result.get("items", []):
            phase = ar.get("status", {}).get("phase", "")
            if phase != "Active":
                continue
            name = ar["metadata"]["name"]
            namespace = ar.get("spec", {}).get("namespace", "default")
            target_cluster = ar.get("spec", {}).get("cluster", get_clusters()[0]["name"])
            expires_at_str = ar.get("status", {}).get("expiresAt", "")
            if not expires_at_str:
                logger.warning(f"⚠️  [{name}] Active request has no expiresAt — cleaning up now on cluster={target_cluster} ns={namespace}")
                asyncio.create_task(cleanup_access(name, namespace, target_cluster=target_cluster))
                continue
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            remaining = (expires_at - now).total_seconds()
            if remaining <= 0:
                logger.info(f"💀 [{name}] already expired — cleaning up now on cluster={target_cluster} ns={namespace}")
                asyncio.create_task(cleanup_access(name, namespace, target_cluster=target_cluster))
            else:
                logger.info(f"⏰ [{name}] rescheduling TTL cleanup in {int(remaining)}s for cluster={target_cluster} ns={namespace}")
                asyncio.create_task(cleanup_after_ttl(name, namespace, int(remaining), target_cluster))
    except Exception as e:
        logger.error(f"💥 failed to reschedule active request cleanups: {e}")

    # Start periodic CRD cleanup background task
    asyncio.create_task(_periodic_crd_cleanup_loop())
    logger.info(f"🧹 periodic CRD cleanup started (retention={CLEANUP_RETENTION_SECONDS}s, phases={CLEANUP_TERMINAL_PHASES})")
    logger.info(f"✅ k8s-janus controller ready on cluster={get_clusters()[0]['name']}")
