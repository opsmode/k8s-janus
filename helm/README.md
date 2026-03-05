# K8s-Janus Helm Chart

[![GitHub release](https://img.shields.io/github/v/release/opsmode/k8s-janus)](https://github.com/opsmode/k8s-janus/releases/latest)

Just-in-Time `kubectl exec` access for Kubernetes. Engineers request temporary pod access through a web UI. Admins approve with one click. The token auto-expires. No permanent permissions. Ever.

## How it works

- **Central cluster** — runs the controller, web UI, and CRDs. Admins approve requests here. Engineers open browser terminals here.
- **Remote clusters** — no Janus workload deployed. The setup script applies a minimal `janus-remote` ServiceAccount + RBAC, issues a scoped token, and stores it as a kubeconfig Secret on the central cluster. The controller reaches out on-demand when access is granted.
- **Multi-namespace** — a single AccessRequest can span multiple namespaces. The controller provisions isolated SA + RoleBinding + token Secret per namespace. The terminal shows a namespace tab strip — one browser session covers all requested namespaces.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- `kubectl` (for port-forwarding to the setup wizard)
