# K8s-Janus Helm Chart

[GitHub](https://github.com/opsmode/k8s-janus) · [Artifact Hub](https://artifacthub.io/packages/search?repo=k8s-janus)

**Just-in-Time `kubectl exec` access for Kubernetes.**
Engineers request temporary pod access through a web UI. Admins approve with one click. The token auto-expires. No permanent permissions. Ever.

## How it works

- **Central cluster** — runs the controller, web UI, and CRDs. Admins approve requests here. Engineers open browser terminals here.
- **Remote clusters** — no Janus workload deployed. The setup script applies a minimal `janus-remote` ServiceAccount + RBAC, issues a scoped token, and stores it as a kubeconfig Secret on the central cluster. The controller reaches out on-demand when access is granted.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- `kubectl`, `python3`, `curl`

## Install

```bash
helm repo add k8s-janus https://opsmode.github.io/k8s-janus
helm repo update
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace
```

Then run the setup script to register your clusters:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/setup-upload.sh)
```

Choose **CLI mode** (terminal only) or **Browser mode** (web wizard with live progress). The script resolves exec-based kubeconfig auth (GKE, EKS, AKS), applies RBAC on each remote cluster, issues scoped tokens, and creates kubeconfig Secrets — no repo clone, no manual YAML.

The controller init container blocks until all kubeconfig Secrets exist — it won't start until setup is complete.

**Select clusters and set display names:**

![Select clusters](https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/static/setup-onboarding.jpeg)

**Live configuration progress:**

![Configuring clusters](https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/static/setup-configuring.jpeg)

**Remove clusters at any time via the wizard:**

![Remove clusters](https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/static/setup-offboarding.jpeg)

## Configuration

### Central cluster identity

| Parameter | Description | Default |
|-----------|-------------|---------|
| `janus.clusterName` | Internal identifier for the central cluster | `central` |
| `janus.clusterDisplayName` | Name shown in the web UI for the central cluster | `Central Cluster` |

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
| `remote.enabled` | Deploy as remote agent only — advanced use, setup script preferred | `false` |

## Security

The chart ships with a hardened default posture:

- **Pod Security Standards** — `restricted` profile enforced at the namespace level
- **RBAC least-privilege** — ClusterRoles scoped to named resources only (`janus-pod-exec`); no wildcard grants
- **NetworkPolicy** — ingress limited to intra-namespace traffic; egress limited to the Kubernetes API server and remote cluster endpoints
- **Non-root containers** — all pods run as non-root with a read-only root filesystem and all capabilities dropped
- **Token isolation** — access tokens stored in Kubernetes Secrets only, never in CRD status or logs
- **Failed phase** — access grants that error out surface as `Failed` on the CRD instead of silently freezing

## Links

- [GitHub](https://github.com/opsmode/k8s-janus)
- [Documentation](https://github.com/opsmode/k8s-janus#readme)
- [Artifact Hub](https://artifacthub.io/packages/search?repo=k8s-janus)
