<div align="center">

<img src="webui/static/k8s-janus-logo.svg" width="120" alt="K8s-Janus logo" />

# K8S-Janus

### *Just-in-Time Kubernetes Pod Access*

[![CI](https://github.com/infroware/k8s-janus/actions/workflows/ci.yaml/badge.svg)](https://github.com/infroware/k8s-janus/actions/workflows/ci.yaml)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/k8s-janus)](https://artifacthub.io/packages/helm/k8s-janus/k8s-janus)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Operator-326CE5?logo=kubernetes&logoColor=white)
[![Helm](https://img.shields.io/badge/Helm-Chart-0F1689?logo=helm&logoColor=white)](https://infroware.github.io/k8s-janus)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-Apache_2.0-blue)

**Engineers request temporary `kubectl exec` access through a web UI.**  
**Admins approve with one click. The token auto-expires.**  
**No permanent permissions. Ever.**

> *In Roman mythology, **Janus** was the god of doorways — watching every passage in both directions.*  
> *He did not block the gate. He governed it.*

</div>

---

## 🎉 What's new in v1.0.7

| | |
|-|-|
| 🎨 | **Kubernetes blue design** — Accent color matches K8s blue (#326CE5); vector SVG logo |
| 🔌 | **WebSocket stability** — Pure ASGI middleware; terminal connections no longer silently dropped |
| ⏱️ | **Terminal timeout** — 15s exec timeout; stuck connections recover automatically |
| 🔧 | **Setup WebSocket** — `/ws/setup/*` correctly bypassed auth; setup wizard works with auth enabled |
| 🗂️ | **Multi-namespace fix** — Pod info now resolves the correct namespace per pod |

---

## 🚨 The Problem

Most Kubernetes access patterns are broken:

| Approach | Problem |
|----------|---------|
| 🔴 Permanent RoleBinding | Over-privileged, forgotten forever |
| 🔴 Sharing cluster-admin | Dangerous, no audit trail |
| 🔴 Manual token creation | Tedious, tokens never revoked |

**K8s-Janus** replaces all of these with a structured, time-limited, fully auditable workflow.

---

## ✨ Features

| | Feature | Detail |
|-|---------|--------|
| 🌐 | **Web Terminal** | Browser-based `kubectl exec` — no local tools, no kubeconfig, no VPN |
| 🖥️ | **Split-Pane** | Two pods side-by-side in one tab with independent shell sessions |
| 📋 | **Pod Logs & Events** | Real-time logs and K8s events in the terminal sidebar |
| ⚡ | **Quick Commands** | Save and replay one-click shell commands per cluster |
| 🎨 | **Colored Prompt** | PS1 auto-injected on connect — cyan `user@host`, blue path |
| 🏢 | **Multi-Cluster** | Manage any number of clusters from one install (GKE, EKS, AKS, vCluster…) |
| 📦 | **Multi-Namespace** | One request covers multiple namespaces; namespace tab strip in terminal |
| ✅ | **One-Click Approval** | Approve, deny, or override TTL from the admin dashboard |
| 🚪 | **Self-Service Withdraw** | Engineers cancel their own Pending or Active requests |
| ⚡ | **Instant Revoke** | Terminate any active session immediately |
| ⏰ | **Auto-Cleanup** | SA + RoleBinding + token Secret deleted on TTL expiry |
| ⏰ | **Pending Auto-Expiry** | Auto-deny requests that go unapproved beyond a configurable limit |
| 🔐 | **Native OIDC/SSO** | Google, GitHub, Entra ID, Okta, GitLab, or any OIDC provider — no oauth2-proxy |
| 📋 | **Full Audit Log** | Every request event, session open/close, command, and revocation logged |
| 🗄️ | **PostgreSQL Backend** | Optional persistent DB — history survives pod restarts |
| 🛡️ | **Security Hardened** | Non-root · read-only FS · all capabilities dropped · NetworkPolicy |

---

## 🔄 How It Works

```
Engineer             Web UI              Controller           Approver
   │                   │                     │                   │
   │── submit ────────▶│                     │                   │
   │  (ns=['a','b'])   │── create CRD ──────▶│                   │
   │                   │                     │── notify ────────▶│
   │                   │                     │    (clicks Approve)│
   │                   │                     │◀── callback ──────│
   │                   │  per-NS: SA + RoleBinding + token Secret │
   │◀── terminal ──────│                     │                   │
   │  (namespace tabs) │                     │                   │
   │   (TTL expires)   │    delete SA + RoleBinding + Secrets    │
```

### Access Lifecycle

```
Pending ──▶ Approved ──▶ Active ──▶ Expired
         ╲▶ Denied       │
         (any state) ──▶ Revoked
         Approved ──▶ Failed  (grant error — check controller logs)
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│              Central Cluster                    │
│                                                 │
│   ┌─────────────┐       ┌──────────────────┐   │
│   │  Controller │       │     Web UI       │   │
│   │  (kopf op.) │       │  (FastAPI+HTMX)  │   │
│   └──────┬──────┘       └────────┬─────────┘   │
│          │  kubeconfig Secrets   │              │
└──────────┼───────────────────────┼─────────────┘
           │                       │
    ┌──────▼───────┐       ┌───────▼──────┐
    │  Cluster A   │       │  Cluster B   │
    │  (any distro)│  ...  │  (any distro)│
    └──────────────┘       └──────────────┘
```

Each target cluster is represented by a kubeconfig stored in a Kubernetes Secret in the `k8s-janus` namespace. Works with any distribution — GKE, EKS, AKS, on-prem, kind, vCluster.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Controller** | Python · [kopf](https://kopf.readthedocs.io/) Kubernetes operator |
| **Web UI** | Python · FastAPI · HTMX · xterm.js |
| **Auth** | Authlib · OIDC/OAuth2 (Google, GitHub, Entra ID, Okta, GitLab, custom) |
| **Packaging** | Helm |
| **CI/CD** | GitHub Actions · Docker |

---

## 🚀 Quick Start

**Prerequisites:** `kubectl` and `helm`.

```bash
helm repo add k8s-janus https://infroware.github.io/k8s-janus
helm repo update
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace
```

### Register remote clusters

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/infroware/k8s-janus/main/webui/setup-upload.sh)
```

Choose **CLI mode** or **Browser mode**. The script:
1. Resolves exec-based auth (GKE, EKS, AKS) to static tokens automatically
2. Applies `janus-remote` RBAC to each remote cluster
3. Issues a scoped 1-year token and stores it as a `<cluster>-kubeconfig` Secret on the central cluster
4. Restarts the controller and web UI so they pick up the new clusters immediately

No cloud-specific setup, no IAM bindings, no repo clone needed.

---

## 🔐 Authentication

By default Janus trusts the `X-Forwarded-Email` header from an upstream proxy. For a self-contained setup, enable native OIDC:

```yaml
oidc:
  enabled: true
  provider: google          # google | github | entra | okta | gitlab | custom
  clientId: "your-client-id"
  clientSecret: "your-client-secret"
  allowedDomains: ["your-org.com"]
```

| Provider | `provider` value | Extra config |
|----------|-----------------|--------------|
| Google | `google` | — |
| GitHub | `github` | — |
| Microsoft Entra ID | `entra` | `tenantId: "your-tenant-id"` |
| Okta | `okta` | `issuerUrl: "https://your-org.okta.com"` |
| GitLab | `gitlab` | — |
| Any OIDC provider | `custom` | `issuerUrl: "https://idp.example.com"` |

`clientSecret` can be supplied inline, via `existingSecret`, or synced from a secret store via `externalSecrets.enabled: true`.

---

## 🗄️ PostgreSQL Backend

By default Janus uses SQLite (ephemeral — data lost on pod restart). For persistent history:

```yaml
postgresql:
  enabled: true
  host: "postgres-host"
  database: "k8s-janus"
  username: "k8s-janus"
```

The password must exist in a Secret named `k8s-janus-postgresql` with key `password`:

```bash
kubectl create secret generic k8s-janus-postgresql \
  --namespace k8s-janus \
  --from-literal=password=your-db-password
```

Or sync it automatically via External Secrets Operator:

```yaml
externalSecrets:
  enabled: true
  secretStore: "my-cluster-secret-store"
postgresql:
  secretKey: "K8S-JANUS-DB-PASSWORD"
```

---

## ⚙️ Configuration Reference

| Field | Default | Description |
|-------|---------|-------------|
| `janus.defaultTtlSeconds` | `3600` | Default access duration in the request form (1h) |
| `janus.maxTtlSeconds` | `28800` | Hard cap engineers cannot exceed (8h) |
| `janus.approvalTtlOptions` | `[3600,7200,14400,28800]` | TTL override choices in the admin approval dropdown |
| `janus.crdRetentionSeconds` | `86400` | Delete Expired/Denied/Revoked CRDs after N seconds |
| `janus.pendingExpirySeconds` | `0` | Auto-deny Pending requests after N seconds (0 = disabled) |
| `janus.idleTimeoutSeconds` | `0` | Terminate idle terminal sessions after N seconds (0 = disabled) |
| `janus.displayTimezone` | `UTC` | IANA timezone for timestamps in the UI |
| `janus.adminEmails` | `[]` | Emails with approve/deny/revoke privileges |
| `janus.excludedNamespaces` | `[k8s-janus, kube-system, …]` | Namespaces hidden from the request form |
| `postgresql.enabled` | `false` | Persistent DB — survives pod restarts |
| `networkPolicy.enabled` | `true` | Restrict egress to K8s API + DNS only |
| `remote.enabled` | `false` | Deploy only RBAC on a target cluster (no controller/webui) |
| `oidc.enabled` | `false` | Enable native OIDC/OAuth2 SSO |
| `webui.authEnabled` | `false` | Trust `X-Forwarded-Email` header from upstream proxy |
| `replicaCount` | `1` | >1 also creates a PodDisruptionBudget |

---

## 🛡️ Security Model

| Control | Implementation |
|---------|---------------|
| 🔑 Token isolation | Token in K8s Secret — never in CRD status or logs |
| 🎯 Least privilege | Scoped RoleBinding per namespace, not ClusterRoleBinding |
| 👤 Non-root | `runAsUser: 1000`, `runAsNonRoot: true` |
| 📁 Immutable FS | `readOnlyRootFilesystem: true` |
| 🚫 No capabilities | `capabilities.drop: [ALL]` |
| 🌐 Network isolation | NetworkPolicy: egress restricted to K8s API (443/6443) and DNS only |
| ⏰ TTL enforcement | Min 10 min · Max 8 hours · Enforced server-side |
| 🔏 Signed chart | Helm chart signed with GPG — verify with `helm install --verify` |
| 📋 Full audit trail | Every session open, close, command, idle timeout, and revocation logged |
| 🛡️ RBAC scoped | Controller ClusterRole restricted to `janus-pod-exec` by `resourceNames` |
| 🔒 Pod Security Standards | `pod-security.kubernetes.io/enforce: restricted` on the `k8s-janus` namespace |

---

## 📋 Observability

Janus logs every lifecycle event — startup, request state transitions, credential provisioning, cleanup, and WebSocket sessions.

```
[INFO] ✅ k8s-janus controller ready on cluster=prod
[INFO] 📥 New AccessRequest [alice-debug-api] from alice@example.com → cluster=prod ns=['default','payments']
[INFO] 🔄 [alice-debug-api] phase transition: Pending → Approved
[INFO] ✅ [alice-debug-api] access GRANTED — requester=alice@example.com cluster=prod ns=['default','payments']
[INFO] 🧹 [alice-debug-api] starting cleanup (TTL expired) on cluster=prod ns=['default','payments']
[INFO] 💀 [alice-debug-api] marked as Expired — all credentials removed
```

---

<div align="center">

Apache 2.0 License · Built with ☕ by [infroware](https://github.com/infroware)

</div>
