# K8s-Janus

**Just-in-Time `kubectl exec` access for Kubernetes.**

Engineers request temporary pod shell access through a web UI. Admins approve with one click. The token auto-expires. No permanent permissions. Ever.

## How it works

- **Central cluster** — runs the controller, web UI, and CRDs. Admins approve requests here. Engineers open browser terminals here.
- **Remote clusters** — no Janus workload deployed. A scoped `janus-remote` ServiceAccount + RBAC is applied automatically, a token issued, and stored as a kubeconfig Secret on the central cluster. The controller reaches out on-demand when access is granted.
- **Multi-namespace** — a single AccessRequest spans multiple namespaces. The controller provisions isolated SA + RoleBinding + token per namespace. The terminal shows a namespace tab strip — one browser session covers all requested namespaces.
- **Audit trail** — every session open, close, command, idle timeout, and revocation is logged.

## Access lifecycle

```
Pending ──▶ Approved ──▶ Active ──▶ Expired
         ╲▶ Denied       │
         (any state) ──▶ Revoked
```

## Security

- Pod Security Standards `restricted` profile enforced at the namespace level
- RBAC least-privilege — ClusterRoles scoped to named resources only, no wildcard grants
- NetworkPolicy — egress limited to Kubernetes API and DNS only
- Non-root containers — read-only root filesystem, all capabilities dropped
- Tokens stored in Kubernetes Secrets only — never in CRD status or logs

## Documentation & Installation

Full setup instructions, configuration reference, screenshots, and changelog:

**→ [github.com/opsmode/k8s-janus](https://github.com/opsmode/k8s-janus)**
