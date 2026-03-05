<div align="center">

<img src="webui/static/k8s-janus-logo-readme.png" width="120" alt="K8s-Janus logo" />

# K8S-Janus

### *Just-in-Time Kubernetes Pod Access*

[![CI](https://github.com/opsmode/k8s-janus/actions/workflows/ci.yaml/badge.svg)](https://github.com/opsmode/k8s-janus/actions/workflows/ci.yaml)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/k8s-janus)](https://artifacthub.io/packages/helm/k8s-janus/k8s-janus)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Operator-326CE5?logo=kubernetes&logoColor=white)
[![Helm](https://img.shields.io/badge/Helm-Chart-0F1689?logo=helm&logoColor=white)](https://opsmode.github.io/k8s-janus)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-Apache_2.0-blue)

**Engineers request temporary `kubectl exec` access through a web UI.**
**Admins approve with one click. The token auto-expires.**
**No permanent permissions. Ever.**

> In Roman mythology, **Janus** was the god of doorways and transitions — watching every passage in both directions.
>
> He did not block the gate. He *governed* it.
>
> **⛩ The gate opens. Then it closes.**

<video src="https://github.com/user-attachments/assets/005e0efc-4dc1-4141-a76c-eba342807d86" controls width="100%"></video>

</div>

---

## 🚨 The Problem

In most Kubernetes environments, granting pod access means either:

| Approach | Problem |
|----------|---------|
| 🔴 Permanent RoleBinding | Over-privileged, forgotten forever |
| 🔴 Sharing cluster-admin | Dangerous, no audit trail |
| 🔴 Manual token creation | Tedious, tokens never get revoked |

**K8s-Janus solves this** with a structured, time-limited, fully auditable access workflow — no permanent permissions granted to anyone.

---

## ✨ Features

| | Feature | Detail |
|-|---------|--------|
| 🌐 | **Web Terminal** | Browser-based `kubectl exec` shell — multi-pane split view, namespace switcher, no local tools needed |
| 🏢 | **Multi-Cluster** | One instance manages multiple clusters — any distribution, any cloud |
| 📦 | **Multi-Namespace** | Request access to multiple namespaces in a single CRD — one approval, one terminal, namespace tabs |
| ✅ | **One-Click Approval** | Admins see pending requests in the dashboard — approve or deny without leaving the browser |
| ⏱️ | **Auto-Cleanup** | ServiceAccount + RoleBinding + token Secret deleted automatically on TTL expiry |
| ⚡ | **Instant Revoke** | Terminate any active session immediately from the admin dashboard |
| ⏰ | **Pending Auto-Expiry** | Optionally auto-deny requests that go unapproved beyond a configurable time limit |
| 🔐 | **Native OIDC/OAuth2** | Built-in SSO — Google, GitHub, Entra ID, Okta, GitLab, or any OIDC provider. No oauth2-proxy needed |
| 👤 | **User Profiles** | Persistent avatars and display names with cross-user visibility |
| 🛡️ | **Security Hardened** | Non-root, read-only FS, all capabilities dropped, NetworkPolicy |
| 🔒 | **No Token Leakage** | Per-namespace scoped tokens stored in K8s Secrets only — never in CRD status or logs |

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
   │   (TTL expires)   │  delete all SA + RoleBinding + Secrets   │
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

Each target cluster is represented by a kubeconfig stored in a Kubernetes Secret in the `k8s-janus` namespace. Works with any Kubernetes distribution — GKE, EKS, AKS, on-prem, kind, vCluster.

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

## 🔐 Security Model

| Control | Implementation |
|---------|---------------|
| 🔑 Token isolation | Token in K8s Secret — never in CRD status or logs |
| 🎯 Least privilege | Scoped RoleBinding per namespace, not ClusterRoleBinding |
| 👤 Non-root | `runAsUser: 1000`, `runAsNonRoot: true` |
| 📁 Immutable FS | `readOnlyRootFilesystem: true` |
| 🚫 No capabilities | `capabilities.drop: [ALL]` |
| 🌐 Network isolation | NetworkPolicy: egress restricted to K8s API (443/6443) and DNS only |
| ⏰ TTL enforcement | Min 10 min · Max 8 hours · Enforced server-side |
| 🔏 Signed images | Helm chart signed with GPG — verify with `helm install --verify` |
| 📋 Full audit trail | Every session open, close, command, idle timeout, and revocation logged |
| 🛡️ RBAC scoped | Controller ClusterRole restricted to `janus-pod-exec` by `resourceNames` — can't create arbitrary ClusterRoles |
| 🔒 Pod Security Standards | `pod-security.kubernetes.io/enforce: restricted` on the `k8s-janus` namespace |

---

## 🚀 Quick Start

**Prerequisites:** `kubectl` and `helm`.

### Install via Helm

```bash
helm repo add k8s-janus https://opsmode.github.io/k8s-janus
helm repo update
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace
```

### Register remote clusters

Run the setup script — it walks you through everything interactively:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/setup-upload.sh)
```

Choose **CLI mode** (terminal only) or **Browser mode** (opens the web wizard). The script:
1. Picks up your local kubeconfig — resolves exec-based auth (GKE, EKS, AKS) to static tokens automatically
2. Asks which cluster is central (where Janus runs) and which are remote targets
3. Applies `janus-remote` RBAC to each remote cluster
4. Issues a scoped 1-year token and creates the `<cluster>-kubeconfig` Secret on the central cluster
5. Restarts the controller and web UI so they pick up the new clusters immediately

No cloud-specific setup, no IAM bindings, no repo clone needed.

**Select central and remote clusters:**

![Select clusters](https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/static/setup-onboarding.jpeg)

**Live configuration progress — RBAC, tokens, secrets, pod restart:**

![Configuring clusters](https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/static/setup-configuring.jpeg)

**Rename or remove clusters at any time from the Edit Clusters panel:**

![Remove clusters](https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/static/setup-offboarding.jpeg)

**Optional — exclude additional namespaces from the request form:**

System namespaces are excluded by default. Add any others to your values:

```yaml
janus:
  excludedNamespaces:
    - k8s-janus
    - kube-system
    - argocd
    - cert-manager
    - monitoring
    - logging
    - ingress-nginx
```

Then redeploy: `helm upgrade k8s-janus ./helm --namespace k8s-janus --reuse-values`

---

## 🔐 Authentication

By default Janus trusts the `X-Forwarded-Email` header injected by an upstream oauth2-proxy or ingress. For a self-contained setup, enable native OIDC:

```yaml
oidc:
  enabled: true
  provider: google          # google | github | entra | okta | gitlab | custom
  clientId: "your-client-id"
  clientSecret: "your-client-secret"
  allowedDomains: ["your-org.com"]   # leave empty to allow any domain
```

Supported providers and required config:

| Provider | `provider` value | Extra config |
|----------|-----------------|--------------|
| Google | `google` | — |
| GitHub | `github` | — |
| Microsoft Entra ID | `entra` | `tenantId: "your-tenant-id"` |
| Okta | `okta` | `issuerUrl: "https://your-org.okta.com"` |
| GitLab | `gitlab` | — |
| Any OIDC provider | `custom` | `issuerUrl: "https://idp.example.com"` |

**Secret handling** — `clientSecret` and `sessionSecret` can be supplied three ways (in priority order):
1. `existingSecret` — point to a pre-existing Secret you manage externally
2. `externalSecrets.enabled: true` — ExternalSecret syncs from GCP/AWS/Vault/etc.
3. Inline values in `oidc.clientSecret` / `oidc.sessionSecret` (auto-generated session secret if blank)

Backwards-compatible: when `oidc.enabled: false`, the `X-Forwarded-Email` path is unchanged.

---

## 📋 Observability

Janus logs everything — startup, every access request lifecycle event, cleanup, and WebSocket sessions. No black boxes.

### Controller

```
[INFO] 🚀 k8s-janus controller starting up on cluster=gke_project_region_cluster
[INFO] DB initialised (SQLite (ephemeral))
[INFO] 🧹 periodic CRD cleanup started (retention=86400s, phases={'Expired', 'Denied', 'Revoked'})
[INFO] ⏰ pending auto-expiry started (limit=4h)
[INFO] ✅ k8s-janus controller ready on cluster=gke_project_region_cluster
[INFO] 🛡️  updated janus-pod-exec ClusterRole on cluster=gke_project_region_cluster

# Engineer submits a request for two namespaces
[INFO] 📥 New AccessRequest [alice-debug-api] from alice@example.com → cluster=prod ns=['default','payments']

# Admin approves → credentials provisioned per namespace automatically
[INFO] 🔄 [alice-debug-api] phase transition: Pending → Approved  (cluster=prod ns=['default','payments'])
[INFO] 🔑 [alice-debug-api] granting access for alice@example.com on cluster=prod ns=default
[INFO] 👤 [alice-debug-api] created ServiceAccount=janus-alice-debug-api in cluster=prod ns=default
[INFO] 🔗 [alice-debug-api] created RoleBinding=janus-alice-debug-api in cluster=prod ns=default
[INFO] 🎟️  [alice-debug-api] issued token for SA=janus-alice-debug-api in cluster=prod, ttl=3600s, expires=2026-03-03T22:08:56Z
[INFO] 🔐 [alice-debug-api] stored token Secret=janus-token-alice-debug-api-default-3a1f9c in ns=k8s-janus
[INFO] ✅ [alice-debug-api] access GRANTED — requester=alice@example.com cluster=prod ns=['default','payments'] expires=2026-03-03T22:08:56Z

# TTL expires → automatic cleanup of all namespaces, no manual action needed
[INFO] 🧹 [alice-debug-api] starting cleanup (TTL expired) on cluster=prod ns=['default','payments']
[INFO] 🗑️  [alice-debug-api] deleted RoleBinding=janus-alice-debug-api from cluster=prod ns=default
[INFO] 🗑️  [alice-debug-api] deleted ServiceAccount=janus-alice-debug-api from cluster=prod ns=default
[INFO] 🗑️  [alice-debug-api] deleted token Secret=janus-token-alice-debug-api-default-3a1f9c from ns=k8s-janus
[INFO] 💀 [alice-debug-api] marked as Expired — all credentials removed from cluster=prod ns=['default','payments']

# Admin revokes an active session
[INFO] 🚫 [alice-debug-api] revoked by admin — triggering immediate cleanup on cluster=prod ns=default
[INFO] 🔒 Revoke signal sent to 1 terminal session(s) for alice-debug-api

# Pending request auto-denied after limit
[INFO] ⏰ [alice-debug-api] auto-denied — pending for 4.1h (limit=4h)
```

### Web UI

```
[INFO] DB initialised (SQLite (ephemeral))
[WARNING] 🔓 K8s-Janus WebUI started in OPEN MODE — AUTH_ENABLED=false
INFO:     Uvicorn running on http://0.0.0.0:8000

# Engineer opens the terminal — kubeconfig loaded, exec session started
[INFO] 🔧 Building client for cluster: gke_project_region_cluster
INFO:     10.0.0.1:54321 - "GET /terminal/prod/alice-debug-api HTTP/1.1" 200 OK

# Session ends (TTL expired or admin revoke)
[INFO] 🔒 Revoke signal sent to 1 terminal session(s) for alice-debug-api
```

---

<div align="center">

Apache 2.0 License · Built with ☕ by [opsmode](https://github.com/opsmode)

</div>
