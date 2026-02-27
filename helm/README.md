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
| `replicaCount` | Number of replicas for controller and webui | `1` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.controller.repository` | Controller image | `opsmode/k8s-janus-controller` |
| `image.controller.tag` | Controller image tag | `latest` |
| `image.webui.repository` | Web UI image | `opsmode/k8s-janus-webui` |
| `image.webui.tag` | Web UI image tag | `latest` |
| `clusters` | List of clusters to manage | see values.yaml |
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
| `externalSecrets.enabled` | Use External Secrets Operator | `false` |
| `postgresql.enabled` | Use PostgreSQL for persistence | `false` |

## Quick Setup

Run the interactive setup script to configure clusters automatically:

```bash
git clone https://github.com/opsmode/k8s-janus
cd k8s-janus
./scripts/setup.sh
```

## Links

- [GitHub](https://github.com/opsmode/k8s-janus)
- [Documentation](https://github.com/opsmode/k8s-janus#readme)
- [Artifact Hub](https://artifacthub.io/packages/search?repo=k8s-janus)
