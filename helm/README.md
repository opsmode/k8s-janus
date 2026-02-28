# K8s-Janus Helm Chart

**Just-in-Time `kubectl exec` access for Kubernetes.**
Engineers request temporary pod access through a web UI. Admins approve with one click. The token auto-expires. No permanent permissions. Ever.

## Install

```bash
helm repo add k8s-janus https://opsmode.github.io/k8s-janus
helm repo update
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace
```

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- `kubectl` access to your cluster(s)

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Replicas for controller and webui deployments | `1` |
| `image.repository` | Container image (controller + webui combined) | `opsmode/k8s-janus` |
| `image.tag` | Image tag | set by CI on release |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `clusters` | List of clusters to manage (first = central) | see values.yaml |
| `clusters[].name` | Cluster identifier (used internally) | required |
| `clusters[].displayName` | Human-readable name shown in the UI | required |
| `clusters[].secretName` | Override kubeconfig Secret name (auto-derived as `<name>-kubeconfig`) | optional |
| `janus.namespace` | Namespace Janus is deployed in | `k8s-janus` |
| `janus.defaultTtlSeconds` | Default access TTL | `3600` |
| `janus.maxTtlSeconds` | Maximum allowed TTL | `28800` |
| `janus.idleTimeoutSeconds` | Idle terminal timeout | `900` |
| `janus.displayTimezone` | Timezone for UI timestamps | `Europe/Berlin` |
| `janus.adminEmails` | Emails with admin access | `[]` |
| `janus.excludedNamespaces` | Namespaces hidden from request form | see values.yaml |
| `service.type` | Web UI service type | `LoadBalancer` |
| `service.port` | Web UI service port | `80` |
| `ingress.enabled` | Enable ingress instead of LoadBalancer | `false` |
| `webui.authEnabled` | Enable OAuth2 proxy auth | `false` |
| `webui.baseUrl` | Public URL for callback links | `""` |
| `kubeconfigSync.enabled` | Auto-sync kubeconfig Secrets from ArgoCD cluster Secrets | `false` |
| `kubeconfigSync.argocdNamespace` | Namespace where ArgoCD stores cluster Secrets | `argocd` |
| `externalSecrets.enabled` | Use External Secrets Operator | `false` |
| `postgresql.enabled` | Use PostgreSQL for persistence | `false` |
| `networkPolicy.enabled` | Deploy NetworkPolicy for controller and webui pods | `true` |
| `remote.enabled` | Remote agent mode (ServiceAccount + RBAC only, no controller/webui) | `false` |

## Cluster Setup

Each cluster in the `clusters:` list needs a kubeconfig Secret named `<name>-kubeconfig` in the `k8s-janus` namespace. There are two ways to provision these:

### Option A — setup.sh (non-ArgoCD)

```bash
./scripts/setup.sh
```

Interactive script that deploys the remote agent, extracts a static token, and creates the kubeconfig Secrets automatically.

### Option B — kubeconfigSync (ArgoCD)

If ArgoCD manages your remote clusters, enable the post-install Job:

```yaml
kubeconfigSync:
  enabled: true
  argocdNamespace: argocd
```

The Job reads ArgoCD's existing cluster Secrets and creates the kubeconfig Secrets automatically — no manual script run needed. Only clusters listed in `clusters:` are synced.

## Remote Agent Mode

To register a remote cluster, deploy the chart with `remote.enabled=true`:

```bash
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace \
  --set remote.enabled=true
```

This creates only the `janus-remote` ServiceAccount and RBAC — no controller or webui. Then run `setup.sh` (or use `kubeconfigSync`) to register the cluster with the central instance.

## Links

- [GitHub](https://github.com/opsmode/k8s-janus)
- [Documentation](https://github.com/opsmode/k8s-janus#readme)
- [Artifact Hub](https://artifacthub.io/packages/search?repo=k8s-janus)
