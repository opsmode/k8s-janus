# K8s-Janus

[![GitHub release](https://img.shields.io/github/v/release/infroware/k8s-janus?style=flat-square&color=6366f1)](https://github.com/infroware/k8s-janus/releases/latest)
[![License](https://img.shields.io/github/license/infroware/k8s-janus?style=flat-square&color=10b981)](https://github.com/infroware/k8s-janus/blob/main/LICENSE)
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
helm repo add k8s-janus https://infroware.github.io/k8s-janus
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
- **Split-pane terminal** — two pods side-by-side in one browser tab
- **Pod logs & events** — view real-time logs and K8s events from the terminal sidebar
- **Quick commands** — personal per-cluster command palette, saved and replayed with one click
- **Multi-cluster** — manage access to any number of remote clusters from one central install
- **Multi-namespace** — single request covers multiple namespaces, namespace tab strip in terminal
- **Instant revoke** — terminate any active session immediately from the admin dashboard
- **Pending auto-expiry** — auto-deny requests that go unapproved past a configurable limit
- **Native OIDC/SSO** — Google, GitHub, Entra ID, Okta, GitLab, or any OIDC provider. No oauth2-proxy required.
- **Audit trail** — every request lifecycle event, session open/close, command, idle timeout, and revocation logged
- **PostgreSQL backend** — optional persistent request history that survives pod restarts
- **GitOps-ready** — pure Helm, no CRD pre-install steps, ArgoCD compatible
- **Least-privilege RBAC** — scoped to `pods/exec` only, no wildcard grants, no cluster-admin

---

## Configuration reference

| Field | Default | Description |
|-------|---------|-------------|
| `janus.defaultTtlSeconds` | `3600` | Default access duration in the request form |
| `janus.maxTtlSeconds` | `28800` | Hard cap engineers cannot exceed (8h) |
| `janus.approvalTtlOptions` | `[3600,7200,14400,28800]` | TTL override choices in the admin approval dropdown |
| `janus.crdRetentionSeconds` | `86400` | Delete Expired/Denied/Revoked CRDs after N seconds |
| `janus.pendingExpirySeconds` | `0` | Auto-deny Pending requests after N seconds (0 = disabled) |
| `janus.idleTimeoutSeconds` | `900` | Terminate idle terminal sessions after N seconds |
| `janus.displayTimezone` | `UTC` | IANA timezone for UI timestamps |
| `janus.adminEmails` | `[]` | Emails with approve/deny/revoke privileges |
| `janus.excludedNamespaces` | system namespaces | Namespaces hidden from the request form |
| `postgresql.enabled` | `false` | Persistent DB for request history |
| `networkPolicy.enabled` | `true` | Restrict egress to K8s API + DNS only |
| `remote.enabled` | `false` | Deploy only RBAC on a target cluster (no controller/webui) |
| `oidc.enabled` | `false` | Enable native OIDC/OAuth2 SSO |
| `oidc.provider` | `""` | `google` \| `github` \| `entra` \| `okta` \| `gitlab` \| `custom` |
| `webui.authEnabled` | `false` | Trust `X-Forwarded-Email` header from upstream proxy |
| `replicaCount` | `1` | >1 also creates a PodDisruptionBudget |

---

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- `kubectl`

---

## Documentation

Full setup guide, OIDC configuration, multi-cluster walkthrough, and screenshots:

**→ [github.com/infroware/k8s-janus](https://github.com/infroware/k8s-janus)**
