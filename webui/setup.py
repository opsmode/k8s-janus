"""
Setup wizard backend for K8s-Janus.

Handles kubeconfig parsing, remote RBAC provisioning, token issuance,
and kubeconfig Secret creation on the central cluster.
"""
import asyncio
import base64
import logging
import os
import re
import tempfile
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
                "  curl -sO http://localhost:8080/setup/upload-helper && bash setup-upload.sh\n\n"
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
    Idempotently apply the janus-remote RBAC resources on a remote cluster.
    Mirrors helm/templates/remote-rbac.yaml (remote.enabled=true).
    """
    labels = {"app.kubernetes.io/managed-by": "janus-setup-wizard",
              "k8s-janus.opsmode.io/managed": "true"}

    # 1. Namespace
    try:
        core_v1.create_namespace(client.V1Namespace(
            metadata=client.V1ObjectMeta(name=namespace, labels=labels)
        ))
        logger.info(f"Created namespace {namespace}")
    except ApiException as e:
        if e.status != 409:
            raise

    # 2. ServiceAccount
    sa = client.V1ServiceAccount(
        metadata=client.V1ObjectMeta(name="janus-remote", namespace=namespace, labels=labels)
    )
    try:
        core_v1.create_namespaced_service_account(namespace=namespace, body=sa)
    except ApiException as e:
        if e.status == 409:
            core_v1.patch_namespaced_service_account("janus-remote", namespace, sa)
        else:
            raise

    # 3. ClusterRole
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
        rbac_v1.create_cluster_role(body=cr)
    except ApiException as e:
        if e.status == 409:
            rbac_v1.patch_cluster_role("janus-remote", cr)
        else:
            raise

    # 4. ClusterRoleBinding
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
        rbac_v1.create_cluster_role_binding(body=crb)
    except ApiException as e:
        if e.status == 409:
            rbac_v1.patch_cluster_role_binding("janus-remote", crb)
        else:
            raise


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
            spec=client.AuthenticationV1TokenRequestSpec(
                expiration_seconds=duration_seconds,
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
# Main async generator
# ---------------------------------------------------------------------------

async def run_setup(
    kubeconfig: dict,
    central_context: str,
    remote_contexts: list[str],
    janus_namespace: str,
) -> AsyncIterator[str]:
    """
    Async generator that yields progress lines.
    Runs all blocking K8s calls in a thread pool to avoid blocking the event loop.
    """
    loop = asyncio.get_event_loop()

    yield f"[INFO] Central cluster: {central_context} (uses in-cluster config — no secret needed)"

    if not remote_contexts:
        yield "[DONE] No remote clusters selected. Single-cluster setup complete."
        return

    errors: list[str] = []
    total = len(remote_contexts)

    for i, context_name in enumerate(remote_contexts, 1):
        slug = slugify(context_name)
        secret_name = f"{slug}-kubeconfig"
        yield f"[INFO] [{i}/{total}] {context_name}"

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
        kc_dict = _build_kubeconfig_dict(slug, server, ca_data, token)
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

    if errors and len(errors) == total:
        yield f"[FATAL] All {total} cluster(s) failed. Check errors above."
    elif errors:
        yield f"[WARN]  {len(errors)} cluster(s) failed: {', '.join(errors)}"
        yield "[DONE] Setup complete (partial) — controller will start for configured clusters."
    else:
        yield "[DONE] Setup complete — Janus is ready."
