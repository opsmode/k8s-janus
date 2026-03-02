"""
Setup wizard backend for K8s-Janus.

Handles kubeconfig parsing, remote RBAC provisioning, token issuance,
kubeconfig Secret creation, pod rollout restart, and live Ready status.
"""
import asyncio
import base64
import logging
import os
import re
import tempfile
import time
from typing import AsyncIterator

import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger("k8s-janus-webui")

# ---------------------------------------------------------------------------
# RBAC rules mirrored from helm/templates/remote-rbac.yaml
# ---------------------------------------------------------------------------
_JANUS_REMOTE_RULES = [
    # List namespaces for the request form dropdown
    {"apiGroups": [""], "resources": ["namespaces"],
     "verbs": ["get", "list"]},
    # Create/delete scoped ServiceAccounts for approved requests
    {"apiGroups": [""], "resources": ["serviceaccounts"],
     "verbs": ["get", "create", "delete"]},
    # Issue time-limited tokens
    {"apiGroups": [""], "resources": ["serviceaccounts/token"],
     "verbs": ["create"]},
    # Create/delete scoped RoleBindings
    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"],
     "verbs": ["get", "create", "delete"]},
    # Manage janus-pod-exec ClusterRole
    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
     "verbs": ["get", "create", "update", "patch", "delete", "escalate"]},
    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
     "resourceNames": ["janus-pod-exec"], "verbs": ["bind"]},
    # Read pods for validation and preview
    {"apiGroups": [""], "resources": ["pods", "pods/log"],
     "verbs": ["get", "list"]},
    # Read/write events
    {"apiGroups": [""], "resources": ["events"],
     "verbs": ["get", "list", "create", "patch", "update"]},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slugify(name: str) -> str:
    """Convert a context/cluster name to a valid Kubernetes resource name."""
    s = name.lower()
    s = re.sub(r"[^a-z0-9-]", "-", s)
    s = re.sub(r"-+", "-", s)
    s = s.strip("-")
    return s[:63]


def parse_kubeconfig(raw_bytes: bytes) -> dict:
    """
    Parse raw kubeconfig bytes. Returns the parsed dict.
    Raises ValueError with a user-friendly message on any validation failure.
    """
    try:
        kc = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}") from e

    if not isinstance(kc, dict):
        raise ValueError("Not a valid kubeconfig file.")
    if not kc.get("contexts"):
        raise ValueError("No contexts found in kubeconfig.")
    if not kc.get("clusters"):
        raise ValueError("No clusters found in kubeconfig.")

    # Detect exec-based auth (e.g. GKE gke-gcloud-auth-plugin) and warn early.
    for user_entry in kc.get("users", []):
        user = user_entry.get("user", {})
        if user.get("exec"):
            raise ValueError(
                "This kubeconfig uses exec-based authentication (e.g. gke-gcloud-auth-plugin) "
                "which cannot be resolved inside the pod.\n\n"
                "Use the upload helper — it resolves auth locally and uploads automatically:\n\n"
                "  curl -s http://localhost:8080/setup/upload-helper | bash\n\n"
                "Or manually export a static-token kubeconfig:\n\n"
                "  kubectl config view --flatten --minify > flat-kube.yaml\n"
                "  TOKEN=$(gcloud auth print-access-token)\n"
                "  python3 -c \"\n"
                "import yaml; kc=yaml.safe_load(open('flat-kube.yaml'))\n"
                "[(u.update({'user':{'token':'$TOKEN'}})) for u in kc.get('users',[])]\n"
                "print(yaml.dump(kc))\" > flat-token-kube.yaml\n\n"
                "Then upload flat-token-kube.yaml."
            )

    return kc


def list_contexts(kubeconfig: dict) -> list[dict]:
    """Return [{name, cluster, user}, ...] from the kubeconfig."""
    result = []
    for entry in kubeconfig.get("contexts", []):
        name = entry.get("name", "")
        ctx = entry.get("context", {})
        result.append({
            "name": name,
            "cluster": ctx.get("cluster", ""),
            "user": ctx.get("user", ""),
        })
    return result


def _extract_server_and_ca(kubeconfig: dict, context_name: str) -> tuple[str, str]:
    """
    Resolve context → cluster reference → extract server URL and base64-encoded CA.
    Raises ValueError if the CA is not embedded (must be a flattened kubeconfig).
    """
    # Find context entry
    ctx_entry = next(
        (c for c in kubeconfig.get("contexts", []) if c["name"] == context_name),
        None,
    )
    if not ctx_entry:
        raise ValueError(f"Context {context_name!r} not found in kubeconfig.")

    cluster_ref = ctx_entry.get("context", {}).get("cluster", "")
    cluster_entry = next(
        (c for c in kubeconfig.get("clusters", []) if c["name"] == cluster_ref),
        None,
    )
    if not cluster_entry:
        raise ValueError(
            f"Cluster {cluster_ref!r} referenced by context {context_name!r} not found."
        )

    cluster_data = cluster_entry.get("cluster", {})
    server = cluster_data.get("server", "")
    if not server:
        raise ValueError(f"No server URL found for cluster {cluster_ref!r}.")

    ca_data = cluster_data.get("certificate-authority-data", "")
    if not ca_data:
        if cluster_data.get("certificate-authority"):
            raise ValueError(
                f"Cluster {cluster_ref!r} uses a CA file path, not embedded data. "
                "Please re-export with:\n\n"
                "  kubectl config view --flatten --minify > flat-kube.yaml"
            )
        if not cluster_data.get("insecure-skip-tls-verify"):
            raise ValueError(
                f"No certificate-authority-data found for cluster {cluster_ref!r}. "
                "Export a flattened kubeconfig with:\n\n"
                "  kubectl config view --flatten --minify > flat-kube.yaml"
            )

    return server, ca_data


def _build_clients_for_context(
    kubeconfig: dict, context_name: str
) -> tuple[client.CoreV1Api, client.RbacAuthorizationV1Api]:
    """
    Build Kubernetes API clients for a specific context from an in-memory kubeconfig.
    Writes to a NamedTemporaryFile, loads config, then unlinks immediately.
    """
    kc_bytes = yaml.dump(kubeconfig).encode()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".yaml")
    try:
        tmp.write(kc_bytes)
        tmp.flush()
        tmp.close()

        cfg = client.Configuration()
        config.load_kube_config(
            config_file=tmp.name,
            context=context_name,
            client_configuration=cfg,
        )
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    api_client = client.ApiClient(configuration=cfg)
    return client.CoreV1Api(api_client=api_client), client.RbacAuthorizationV1Api(api_client=api_client)


def _get_central_core_v1() -> client.CoreV1Api:
    """Return a CoreV1Api using in-cluster config (webui's own SA)."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


# ---------------------------------------------------------------------------
# Remote RBAC provisioning
# ---------------------------------------------------------------------------

def _apply_remote_rbac(
    core_v1: client.CoreV1Api,
    rbac_v1: client.RbacAuthorizationV1Api,
    namespace: str,
) -> None:
    """
    Force-recreate the janus-remote RBAC resources on a remote cluster.
    Delete-then-create ensures stale rules/subjects are always replaced.
    Mirrors helm/templates/remote-rbac.yaml (remote.enabled=true).
    """
    labels = {"app.kubernetes.io/managed-by": "janus-setup-wizard",
              "k8s-janus.opsmode.io/managed": "true"}

    # 1. Namespace — create if missing (409 = already exists, fine)
    try:
        core_v1.create_namespace(client.V1Namespace(
            metadata=client.V1ObjectMeta(name=namespace, labels=labels)
        ))
        logger.info(f"Created namespace {namespace}")
    except ApiException as e:
        if e.status != 409:
            raise

    # 2. ServiceAccount — delete + recreate for clean state
    try:
        core_v1.delete_namespaced_service_account("janus-remote", namespace)
    except ApiException as e:
        if e.status != 404:
            raise
    core_v1.create_namespaced_service_account(
        namespace=namespace,
        body=client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(name="janus-remote", namespace=namespace, labels=labels)
        ),
    )

    # 3. ClusterRole — delete + recreate
    rules = [
        client.V1PolicyRule(
            api_groups=r["apiGroups"],
            resources=r["resources"],
            verbs=r["verbs"],
            resource_names=r.get("resourceNames"),
        )
        for r in _JANUS_REMOTE_RULES
    ]
    cr = client.V1ClusterRole(
        metadata=client.V1ObjectMeta(name="janus-remote", labels=labels),
        rules=rules,
    )
    try:
        rbac_v1.delete_cluster_role("janus-remote")
    except ApiException as e:
        if e.status != 404:
            raise
    rbac_v1.create_cluster_role(body=cr)

    # 4. ClusterRoleBinding — delete + recreate
    crb = client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name="janus-remote", labels=labels),
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io",
            kind="ClusterRole",
            name="janus-remote",
        ),
        subjects=[client.RbacV1Subject(
            kind="ServiceAccount",
            name="janus-remote",
            namespace=namespace,
        )],
    )
    try:
        rbac_v1.delete_cluster_role_binding("janus-remote")
    except ApiException as e:
        if e.status != 404:
            raise
    rbac_v1.create_cluster_role_binding(body=crb)


def _issue_token(
    core_v1: client.CoreV1Api,
    namespace: str,
    duration_seconds: int = 31_536_000,  # 1 year
) -> str:
    """Issue a TokenRequest for the janus-remote SA. Returns the JWT string."""
    resp = core_v1.create_namespaced_service_account_token(
        name="janus-remote",
        namespace=namespace,
        body=client.AuthenticationV1TokenRequest(
            spec=client.V1TokenRequestSpec(
                expiration_seconds=duration_seconds,
                audiences=[],
            )
        ),
    )
    return resp.status.token


def _build_kubeconfig_dict(
    slug: str, server: str, ca_data_b64: str, token: str
) -> dict:
    """Build the kubeconfig dict stored in the Secret (matches setup.sh format)."""
    cluster: dict = {"server": server}
    if ca_data_b64:
        cluster["certificate-authority-data"] = ca_data_b64
    else:
        cluster["insecure-skip-tls-verify"] = True

    return {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": slug, "cluster": cluster}],
        "contexts": [{"name": slug, "context": {"cluster": slug, "user": "janus-remote"}}],
        "current-context": slug,
        "users": [{"name": "janus-remote", "user": {"token": token}}],
    }


def _upsert_kubeconfig_secret(
    central_core_v1: client.CoreV1Api,
    secret_name: str,
    namespace: str,
    kc_dict: dict,
) -> None:
    """Create or replace the kubeconfig Secret on the central cluster."""
    kc_yaml = yaml.dump(kc_dict)
    kc_b64 = base64.b64encode(kc_yaml.encode()).decode()

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            labels={
                "k8s-janus.opsmode.io/managed": "true",
                "app.kubernetes.io/managed-by": "janus-setup-wizard",
            },
        ),
        type="Opaque",
        data={"kubeconfig": kc_b64},
    )
    try:
        central_core_v1.create_namespaced_secret(namespace=namespace, body=secret)
    except ApiException as e:
        if e.status == 409:
            central_core_v1.replace_namespaced_secret(
                name=secret_name, namespace=namespace, body=secret
            )
        else:
            raise


# ---------------------------------------------------------------------------
# Setup completion check
# ---------------------------------------------------------------------------

def is_setup_complete(clusters: list[dict], janus_namespace: str) -> bool:
    """
    Returns True if all expected kubeconfig secrets exist on the central cluster.
    Single-cluster installs (no remotes) are always considered complete.
    """
    if len(clusters) <= 1:
        return True

    try:
        core_v1 = _get_central_core_v1()
    except Exception as e:
        logger.warning(f"is_setup_complete: could not build client: {e}")
        return False

    for cluster in clusters[1:]:
        secret_name = cluster.get("secretName") or f"{cluster['name']}-kubeconfig"
        try:
            core_v1.read_namespaced_secret(name=secret_name, namespace=janus_namespace)
        except ApiException as e:
            if e.status == 404:
                return False
            logger.warning(f"is_setup_complete: error reading {secret_name}: {e}")
            return False
        except Exception as e:
            logger.warning(f"is_setup_complete: unexpected error: {e}")
            return False

    return True


# ---------------------------------------------------------------------------
# Cluster removal
# ---------------------------------------------------------------------------

def _revoke_cluster_access(
    cluster_name: str,
    janus_namespace: str,
    core_v1_central,
    custom_api,
    kubeconfig: dict | None,
    remote_context: str | None,
) -> list[str]:
    """
    Revoke all Active/Approved/Pending AccessRequests targeting cluster_name.
    For each: delete SA + RoleBinding on remote cluster, delete token Secret on
    central, and patch AccessRequest status → Revoked.
    """
    lines: list[str] = []
    CRD_GROUP   = "k8s-janus.opsmode.io"
    CRD_VERSION = "v1alpha1"

    try:
        result = custom_api.list_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests",
        )
        items = result.get("items", [])
    except Exception as e:
        lines.append(f"[WARN]  Could not list AccessRequests: {e}")
        return lines

    target_phases = {"Active", "Approved", "Pending"}
    affected = [
        ar for ar in items
        if ar.get("spec", {}).get("cluster", "") == cluster_name
        and ar.get("status", {}).get("phase", "") in target_phases
    ]

    if not affected:
        lines.append(f"[INFO]   No active/pending access requests for {cluster_name}")
        return lines

    lines.append(f"[INFO]   Revoking {len(affected)} access request(s) for {cluster_name}...")

    # Build remote client once if we have credentials
    core_v1_remote = rbac_v1_remote = None
    if kubeconfig and remote_context:
        try:
            core_v1_remote, rbac_v1_remote = _build_clients_for_context(kubeconfig, remote_context)
        except Exception as e:
            lines.append(f"[WARN]  Could not connect to remote for SA/RoleBinding cleanup: {e}")

    for ar in affected:
        ar_name   = ar.get("metadata", {}).get("name", "")
        namespace = ar.get("spec", {}).get("namespace", "")

        # Delete RoleBinding on remote
        if rbac_v1_remote and namespace:
            try:
                rbac_v1_remote.delete_namespaced_role_binding(name=ar_name, namespace=namespace)
            except ApiException as e:
                if e.status != 404:
                    lines.append(f"[WARN]  Could not delete RoleBinding {ar_name}: {e.reason}")

        # Delete ServiceAccount on remote (immediately invalidates the token)
        if core_v1_remote and namespace:
            try:
                core_v1_remote.delete_namespaced_service_account(name=ar_name, namespace=namespace)
            except ApiException as e:
                if e.status != 404:
                    lines.append(f"[WARN]  Could not delete SA {ar_name}: {e.reason}")

        # Delete token Secret on central
        token_secret = ar.get("status", {}).get("tokenSecret", f"janus-token-{ar_name}")
        if token_secret:
            try:
                core_v1_central.delete_namespaced_secret(name=token_secret, namespace=janus_namespace)
            except ApiException as e:
                if e.status != 404:
                    lines.append(f"[WARN]  Could not delete token secret {token_secret}: {e.reason}")

        # Patch AccessRequest status → Revoked
        try:
            custom_api.patch_cluster_custom_object_status(
                group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", name=ar_name,
                body={"status": {"phase": "Revoked", "message": f"Cluster {cluster_name} was offboarded"}},
            )
            lines.append(f"[OK]   Revoked access request {ar_name}")
        except Exception as e:
            lines.append(f"[WARN]  Could not patch status for {ar_name}: {e}")

    return lines


def remove_cluster(
    cluster_name: str,
    janus_namespace: str,
    kubeconfig: dict | None = None,
    remote_context: str | None = None,
) -> list[str]:
    """
    Remove a remote cluster from Janus:
      1. Revoke all Active/Approved/Pending AccessRequests targeting the cluster.
      2. Delete the kubeconfig Secret on the central cluster.
      3. If a kubeconfig/context is provided, delete the janus-remote SA,
         ClusterRole, ClusterRoleBinding, and the k8s-janus Namespace on the remote.
    Returns a list of log lines.
    """
    lines: list[str] = []
    secret_name = f"{cluster_name}-kubeconfig"

    core_v1 = _get_central_core_v1()
    custom_api = client.CustomObjectsApi(api_client=core_v1.api_client)

    # Step 1: revoke all access to this cluster immediately
    lines += _revoke_cluster_access(
        cluster_name, janus_namespace, core_v1, custom_api, kubeconfig, remote_context
    )

    # Step 2: delete kubeconfig secret on central
    try:
        core_v1.delete_namespaced_secret(name=secret_name, namespace=janus_namespace)
        lines.append(f"[OK]   Deleted secret {secret_name}")
    except ApiException as e:
        if e.status == 404:
            lines.append(f"[INFO]   Secret {secret_name} not found (already removed)")
        else:
            lines.append(f"[ERROR] Could not delete secret {secret_name}: {e.reason}")

    # Step 2: clean up RBAC on remote if we have credentials
    if kubeconfig and remote_context:
        try:
            core_v1_r, rbac_v1_r = _build_clients_for_context(kubeconfig, remote_context)

            # ClusterRoleBinding
            try:
                rbac_v1_r.delete_cluster_role_binding("janus-remote")
                lines.append("[OK]   Deleted ClusterRoleBinding janus-remote")
            except ApiException as e:
                if e.status != 404:
                    lines.append(f"[WARN]  Could not delete ClusterRoleBinding: {e.reason}")

            # ClusterRole
            try:
                rbac_v1_r.delete_cluster_role("janus-remote")
                lines.append("[OK]   Deleted ClusterRole janus-remote")
            except ApiException as e:
                if e.status != 404:
                    lines.append(f"[WARN]  Could not delete ClusterRole: {e.reason}")

            # ServiceAccount
            try:
                core_v1_r.delete_namespaced_service_account("janus-remote", janus_namespace)
                lines.append("[OK]   Deleted ServiceAccount janus-remote")
            except ApiException as e:
                if e.status != 404:
                    lines.append(f"[WARN]  Could not delete ServiceAccount: {e.reason}")

            # Namespace (only delete if it's the janus namespace and nothing critical remains)
            try:
                core_v1_r.delete_namespace(janus_namespace)
                lines.append(f"[OK]   Deleted namespace {janus_namespace} on remote cluster")
            except ApiException as e:
                if e.status == 404:
                    pass
                elif e.status == 409:
                    lines.append(f"[WARN]  Namespace {janus_namespace} not empty, skipped deletion")
                else:
                    lines.append(f"[WARN]  Could not delete namespace: {e.reason}")

        except Exception as e:
            lines.append(f"[WARN]  Could not clean remote RBAC (non-fatal): {e}")
            lines.append("[INFO]   Kubeconfig secret was still deleted.")

    return lines


# ---------------------------------------------------------------------------
# Pod rollout restart + Ready polling
# ---------------------------------------------------------------------------

_ROLLOUT_ANNOTATION = "kubectl.kubernetes.io/restartedAt"


def _rollout_restart_deployments(namespace: str) -> list[str]:
    """
    Patch both janus-controller and janus-webui deployments with a restartedAt
    annotation to trigger a rolling restart. Returns list of restarted names.
    """
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    apps_v1 = client.AppsV1Api()

    now_iso = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {_ROLLOUT_ANNOTATION: now_iso}
                }
            }
        }
    }

    restarted = []
    try:
        deps = apps_v1.list_namespaced_deployment(namespace=namespace)
        for dep in deps.items:
            name = dep.metadata.name
            if "janus" in name:
                apps_v1.patch_namespaced_deployment(name=name, namespace=namespace, body=patch)
                logger.info(f"Triggered rollout restart: {name}")
                restarted.append(name)
    except ApiException as e:
        logger.warning(f"rollout restart failed: {e}")
    return restarted


def _poll_deployment_ready(namespace: str, timeout: int = 120) -> dict[str, bool]:
    """
    Poll janus deployments until all pods are Ready or timeout.
    Returns {deployment_name: is_ready}.
    """
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    apps_v1 = client.AppsV1Api()

    deadline = time.monotonic() + timeout
    results: dict[str, bool] = {}

    while time.monotonic() < deadline:
        try:
            deps = apps_v1.list_namespaced_deployment(namespace=namespace)
            results = {}
            for dep in deps.items:
                name = dep.metadata.name
                if "janus" not in name:
                    continue
                desired   = dep.spec.replicas or 1
                ready     = dep.status.ready_replicas or 0
                updated   = dep.status.updated_replicas or 0
                available = dep.status.available_replicas or 0
                results[name] = (ready >= desired and updated >= desired and available >= desired)

            if all(results.values()) and results:
                return results
        except Exception as e:
            logger.debug(f"_poll_deployment_ready: {e}")

        time.sleep(3)

    return results


# ---------------------------------------------------------------------------
# Stale secret cleanup
# ---------------------------------------------------------------------------

def _cleanup_stale_secrets(
    central_core_v1: client.CoreV1Api,
    active_cluster_names: set,
    namespace: str,
) -> int:
    """
    Delete kubeconfig secrets in `namespace` that are labeled managed=true
    but whose cluster name is NOT in `active_cluster_names`.
    Returns the number of secrets deleted.
    """
    try:
        secrets = central_core_v1.list_namespaced_secret(
            namespace=namespace,
            label_selector="k8s-janus.opsmode.io/managed=true",
        )
    except ApiException:
        return 0

    deleted = 0
    for s in secrets.items:
        name = s.metadata.name or ""
        if not name.endswith("-kubeconfig"):
            continue
        cluster_name = name[: -len("-kubeconfig")]
        if cluster_name in active_cluster_names:
            continue
        try:
            central_core_v1.delete_namespaced_secret(name=name, namespace=namespace)
            logger.info(f"Deleted stale secret: {name}")
            deleted += 1
        except ApiException as e:
            if e.status != 404:
                logger.warning(f"Could not delete stale secret {name}: {e}")
    return deleted


# ---------------------------------------------------------------------------
# Main async generator
# ---------------------------------------------------------------------------

async def run_setup(
    kubeconfig: dict,
    central_context: str,
    central_name: str,       # optional display name / slug for central cluster
    remote_contexts: list,   # list of {"context": str, "cluster_name": str}
    janus_namespace: str,
) -> AsyncIterator[str]:
    """
    Async generator that yields progress lines.
    Runs all blocking K8s calls in a thread pool to avoid blocking the event loop.
    """
    loop = asyncio.get_event_loop()

    central_display = central_name or central_context
    yield f"[INFO] Central cluster: {central_display} (uses in-cluster config — no secret needed)"

    if not remote_contexts:
        yield "[DONE] No remote clusters selected. Single-cluster setup complete."
        return

    errors: list[str] = []
    total = len(remote_contexts)

    for i, remote in enumerate(remote_contexts, 1):
        context_name = remote["context"]
        cluster_name = remote["cluster_name"]
        secret_name  = f"{cluster_name}-kubeconfig"
        yield f"[INFO] [{i}/{total}] {context_name} → {cluster_name}"

        # --- Connectivity check ---
        try:
            core_v1, rbac_v1 = await loop.run_in_executor(
                None, _build_clients_for_context, kubeconfig, context_name
            )
        except Exception as e:
            yield f"[ERROR]   Cannot load context {context_name!r}: {e}"
            errors.append(context_name)
            continue

        yield "[INFO]   Checking connectivity..."
        try:
            await loop.run_in_executor(None, core_v1.list_namespace)
            yield "[OK]    Cluster reachable"
        except Exception as e:
            yield f"[ERROR]   Cannot reach cluster: {e}"
            errors.append(context_name)
            continue

        # --- Apply RBAC ---
        yield "[INFO]   Applying RBAC resources (SA + ClusterRole + ClusterRoleBinding)..."
        try:
            await loop.run_in_executor(
                None, _apply_remote_rbac, core_v1, rbac_v1, janus_namespace
            )
            yield "[OK]    RBAC applied"
        except Exception as e:
            yield f"[ERROR]   RBAC apply failed: {e}"
            errors.append(context_name)
            continue

        # --- Issue token ---
        yield "[INFO]   Issuing token for janus-remote SA (1 year)..."
        try:
            token = await loop.run_in_executor(
                None, _issue_token, core_v1, janus_namespace
            )
            yield "[OK]    Token issued"
        except Exception as e:
            yield f"[ERROR]   Token issuance failed: {e}"
            errors.append(context_name)
            continue

        # --- Extract server/CA from kubeconfig ---
        try:
            server, ca_data = _extract_server_and_ca(kubeconfig, context_name)
        except ValueError as e:
            yield f"[ERROR]   {e}"
            errors.append(context_name)
            continue

        # --- Build + store kubeconfig secret ---
        kc_dict = _build_kubeconfig_dict(cluster_name, server, ca_data, token)
        yield f"[INFO]   Creating Secret {secret_name!r} on central cluster..."
        try:
            central_core_v1 = await loop.run_in_executor(None, _get_central_core_v1)
            await loop.run_in_executor(
                None, _upsert_kubeconfig_secret,
                central_core_v1, secret_name, janus_namespace, kc_dict,
            )
            yield f"[OK]    Secret {secret_name!r} ready"
        except Exception as e:
            yield f"[ERROR]   Failed to create Secret: {e}"
            errors.append(context_name)
            continue

    # --- Cleanup stale kubeconfig secrets for clusters no longer in this run ---
    configured_names = {r["cluster_name"] for r in remote_contexts if r["context"] not in errors}
    if configured_names:
        yield "[INFO] Cleaning up stale kubeconfig secrets..."
        try:
            central_core_v1_cleanup = await loop.run_in_executor(None, _get_central_core_v1)
            stale_count = await loop.run_in_executor(
                None, _cleanup_stale_secrets, central_core_v1_cleanup, configured_names, janus_namespace
            )
            if stale_count:
                yield f"[OK]   Removed {stale_count} stale secret(s)"
            else:
                yield "[INFO]   No stale secrets found"
        except Exception as e:
            yield f"[WARN]  Stale secret cleanup failed (non-fatal): {e}"

    if errors and len(errors) == total:
        yield f"[FATAL] All {total} cluster(s) failed. Check errors above."
        return

    # --- Rollout restart controller + webui ---
    yield "[INFO] Restarting controller and webui pods..."
    try:
        restarted = await loop.run_in_executor(
            None, _rollout_restart_deployments, janus_namespace
        )
        if restarted:
            for dep_name in restarted:
                yield f"[RESTART] {dep_name}"
            yield "[INFO]   Waiting for pods to become Ready (up to 2 min)..."
            ready_map = await loop.run_in_executor(
                None, _poll_deployment_ready, janus_namespace, 120
            )
            for dep_name, is_ready in sorted(ready_map.items()):
                if is_ready:
                    yield f"[READY]  {dep_name} ✓"
                else:
                    yield f"[WARN]   {dep_name} not ready within timeout (check logs)"
        else:
            yield "[WARN]  No janus deployments found to restart"
    except Exception as e:
        yield f"[WARN]  Pod restart failed (non-fatal): {e}"

    if errors:
        yield f"[WARN]  {len(errors)} cluster(s) failed: {', '.join(errors)}"
        yield "[DONE] Setup complete (partial) — controller will start for configured clusters."
    else:
        yield "[DONE] Setup complete — Janus is ready."
