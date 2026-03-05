# K8s-Janus

[![GitHub release](https://img.shields.io/github/v/release/opsmode/k8s-janus?style=flat-square&color=6366f1)](https://github.com/opsmode/k8s-janus/releases/latest)
[![License](https://img.shields.io/github/license/opsmode/k8s-janus?style=flat-square&color=10b981)](https://github.com/opsmode/k8s-janus/blob/main/LICENSE)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/k8s-janus&style=flat-square)](https://artifacthub.io/packages/helm/k8s-janus/k8s-janus)

> **Just-in-Time `kubectl exec` access for Kubernetes.**
> Engineers request temporary pod access through a web UI. Admins approve with one click. The token auto-expires. No permanent permissions. Ever.

---

## What problem does it solve?

Giving engineers permanent `kubectl exec` access is a security risk. Giving them nothing blocks incident response. **K8s-Janus** sits in the middle:

| Without Janus | With Janus |
|---|---|
| Permanent exec permissions | Time-limited tokens only |
| No approval workflow | One-click approve / deny |
| No audit trail | Every command logged |
| Manual RBAC cleanup | Auto-revoked on expiry |

---

## How it works

```
Engineer submits request → Admin approves → Controller issues scoped token
                                         → Token expires → Access removed automatically
```

- **Central cluster** — runs the controller, web UI, and CRDs. Admins approve here. Engineers open browser terminals here.
- **Remote clusters** — zero Janus workload. The setup wizard applies a minimal `janus-remote` ServiceAccount + RBAC, issues a scoped token, and stores it as a kubeconfig Secret on the central cluster.
- **Multi-namespace** — a single `AccessRequest` spans multiple namespaces. The controller provisions an isolated SA + RoleBinding + token per namespace. The browser terminal shows a namespace tab strip.

### Access lifecycle

```
Pending ──▶ Approved ──▶ Active ──▶ Expired
         ╲▶ Denied       │
         (any state) ──▶ Revoked
```

---

## Quick install

```bash
helm repo add k8s-janus https://opsmode.github.io/k8s-janus
helm repo update
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace
```

Then port-forward and open the setup wizard:

```bash
kubectl port-forward -n k8s-janus svc/janus-webui 8080:80
open http://localhost:8080/setup
```

---

## Key features

- **Web terminal** — browser-based `kubectl exec` shell, no local kubeconfig needed
- **Multi-cluster** — manage access to any number of remote clusters from one central install
- **Native OIDC/SSO** — Google, GitHub, Entra ID, Okta, GitLab, or any OIDC provider. No oauth2-proxy required.
- **Audit trail** — every session open, close, command, idle timeout, and revocation is logged
- **GitOps-ready** — pure Helm, no CRD pre-install steps, ArgoCD compatible
- **Least-privilege RBAC** — scoped to `pods/exec` only, no wildcard grants, no cluster-admin

---

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- `kubectl`

---

## Documentation

Full configuration reference, multi-cluster setup guide, OIDC setup, and screenshots:

**→ [github.com/opsmode/k8s-janus](https://github.com/opsmode/k8s-janus)**
