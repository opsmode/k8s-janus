# K8s-Janus Helm Chart

[GitHub](https://github.com/opsmode/k8s-janus) · [Artifact Hub](https://artifacthub.io/packages/search?repo=k8s-janus)

**Just-in-Time `kubectl exec` access for Kubernetes.**
Engineers request temporary pod access through a web UI. Admins approve with one click. The token auto-expires. No permanent permissions. Ever.

## How it works

K8s-Janus has two roles:

- **Central cluster** — runs the controller, web UI, and CRDs. This is where admins approve requests and engineers open terminals.
- **Remote cluster** — runs only a lightweight agent (ServiceAccount + RBAC). The central controller connects to it when access is granted.

You need at least one central install. Add a remote agent on every additional cluster you want to manage.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- `kubectl` access to your cluster(s)

## Install

### 1. Central cluster

```bash
helm repo add k8s-janus https://opsmode.github.io/k8s-janus
helm repo update
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace
```

### 2. Remote clusters (optional)

On each additional cluster, deploy only the agent — no controller or web UI:

```bash
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace \
  --set remote.enabled=true
```

After deploying the agent, register the cluster with the central instance using one of the two options below.

## Registering remote clusters

The central controller needs a kubeconfig Secret for each remote cluster, named `<cluster-name>-kubeconfig`, in the `k8s-janus` namespace.

### Option A — setup.sh (recommended for most setups)

Run the interactive script from the central cluster:

```bash
./scripts/setup.sh
```

It deploys the remote agent, extracts a scoped token, and creates the kubeconfig Secret automatically.

### Option B — kubeconfigSync (ArgoCD users)

If ArgoCD already manages your remote clusters, skip the script entirely. Enable the post-install Job and it will create the kubeconfig Secrets from ArgoCD's existing cluster Secrets:

```yaml
kubeconfigSync:
  enabled: true
  argocdNamespace: argocd
```

> **Note:** The `name` field in each `clusters:` entry must exactly match the cluster name registered in ArgoCD. Verify with:
> ```bash
> kubectl get secrets -n argocd -l argocd.argoproj.io/secret-type=cluster -o jsonpath='{.items[*].metadata.name}'
> ```

## Configuration

### Clusters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `clusters` | List of clusters to manage — first entry is always the central cluster | see values.yaml |
| `clusters[].name` | Cluster identifier used internally and to find the kubeconfig Secret | required |
| `clusters[].displayName` | Name shown in the web UI | required |
| `clusters[].secretName` | Override kubeconfig Secret name (default: `<name>-kubeconfig`) | optional |

### Access policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `janus.adminEmails` | Email addresses with admin (approve/deny) access | `[]` |
| `janus.defaultTtlSeconds` | Default access duration | `3600` |
| `janus.maxTtlSeconds` | Maximum access duration a user can request | `28800` |
| `janus.idleTimeoutSeconds` | Auto-revoke terminal after this many seconds idle | `900` |
| `janus.excludedNamespaces` | Namespaces hidden from the request form | see values.yaml |
| `janus.displayTimezone` | Timezone for UI timestamps | `Europe/Berlin` |

### Web UI

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type for the web UI | `LoadBalancer` |
| `service.port` | Service port | `80` |
| `ingress.enabled` | Use an Ingress instead of LoadBalancer | `false` |
| `webui.authEnabled` | Enable OAuth2 proxy authentication | `false` |
| `webui.baseUrl` | Public URL used in callback links | `""` |

### Persistence

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.enabled` | Use PostgreSQL for audit log persistence | `false` |
| `externalSecrets.enabled` | Use External Secrets Operator for DB credentials | `false` |

### Infrastructure

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Replicas for controller and webui | `1` |
| `image.repository` | Container image | `opsmode/k8s-janus` |
| `image.tag` | Image tag | set by CI on release |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `networkPolicy.enabled` | Deploy NetworkPolicy for all pods | `true` |
| `pdb.minAvailable` | Min available pods during disruptions (requires `replicaCount > 1`) | `1` |
| `remote.enabled` | Deploy as remote agent only (no controller/webui) | `false` |
| `kubeconfigSync.enabled` | Enable ArgoCD kubeconfig sync Job | `false` |
| `kubeconfigSync.argocdNamespace` | Namespace where ArgoCD stores cluster Secrets | `argocd` |

## Security

The chart ships with a hardened default posture:

- **Pod Security Standards** — `restricted` profile enforced at the namespace level
- **RBAC least-privilege** — ClusterRoles scoped to named resources only (`janus-pod-exec`); no wildcard grants
- **NetworkPolicy** — ingress limited to intra-namespace traffic; egress limited to the Kubernetes API server and remote cluster endpoints
- **Non-root containers** — all pods run as non-root with a read-only root filesystem and dropped capabilities
- **Failed phase** — access grants that error out surface as `Failed` on the CRD instead of silently freezing

## Links

- [GitHub](https://github.com/opsmode/k8s-janus)
- [Documentation](https://github.com/opsmode/k8s-janus#readme)
- [Artifact Hub](https://artifacthub.io/packages/search?repo=k8s-janus)
