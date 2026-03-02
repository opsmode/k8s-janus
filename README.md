<div align="center">

<img src="webui/static/k8s-janus-logo-readme.png" width="120" alt="K8s-Janus logo" />

# K8S-Janus

### *Just-in-Time Kubernetes Pod Access*

[![CI](https://github.com/opsmode/k8s-janus/actions/workflows/ci.yaml/badge.svg)](https://github.com/opsmode/k8s-janus/actions/workflows/ci.yaml)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/k8s-janus)](https://artifacthub.io/packages/helm/k8s-janus/k8s-janusf)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Operator-326CE5?logo=kubernetes&logoColor=white)
[![Helm](https://img.shields.io/badge/Helm-Chart-0F1689?logo=helm&logoColor=white)](https://opsmode.github.io/k8s-janus)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-AGPL_v3-blue)

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
| 🌐 | **Web Terminal** | Browser-based `kubectl exec` shell — multi-pane split view, no local tools needed |
| 🏢 | **Multi-Cluster** | One instance manages multiple clusters — any distribution, any cloud |
| ✅ | **One-Click Approval** | Approvers get a notification — approve or deny without leaving the browser |
| ⏱️ | **Auto-Cleanup** | ServiceAccount + RoleBinding + token Secret deleted automatically on TTL expiry |
| ⚡ | **Instant Revoke** | Terminate any active session immediately from the admin dashboard |
| 🛡️ | **Security Hardened** | Non-root, read-only FS, all capabilities dropped, NetworkPolicy |
| 🔒 | **No Token Leakage** | Token stored in K8s Secret only — never in CRD status or logs |

---

## 🔄 How It Works

```
Engineer             Web UI              Controller           Approver
   │                   │                     │                   │
   │── submit ────────▶│                     │                   │
   │                   │── create CRD ──────▶│                   │
   │                   │                     │── notify ────────▶│
   │                   │                     │    (clicks Approve)│
   │                   │                     │◀── callback ──────│
   │                   │  create SA + RoleBinding + token         │
   │◀── terminal ──────│                     │                   │
   │   (TTL expires)   │   delete SA + RoleBinding + Secret       │
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

### Option A — Web Setup Wizard (recommended)

Run the setup script — it walks you through everything interactively:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/setup-upload.sh)
```

The script will:
1. Ask whether you prefer **CLI mode** (runs entirely in the terminal) or **Browser mode** (opens the web wizard)
2. Ask you to pick a **central cluster** (where Janus runs)
3. Resolve exec-based auth (GKE, EKS, AKS) to static tokens automatically — no cloud SDK needed inside the pod
4. Apply `janus-remote` RBAC to each remote cluster
5. Issue a scoped 1-year token and create the `<cluster>-kubeconfig` Secret on the central cluster

No cloud-specific setup, no IAM bindings, no repo clone needed.

### Option B — setup.sh (scripted / CI use)

For headless or CI environments:

```bash
./scripts/setup.sh
```

Deploys the remote agent, applies RBAC, extracts tokens, and creates kubeconfig Secrets. Optionally auto-patches `helm/values.yaml` with the `clusters:` list if `yq` is installed.

**Optional — exclude additional namespaces from the request form:**

System and GKE namespaces are excluded by default. Add any others to your values:

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

## 📋 Observability

Janus logs everything — startup, every access request lifecycle event, cleanup, and WebSocket sessions. No black boxes.

### Controller

```
[INFO] 🚀 k8s-janus controller starting up on cluster=gke_project_region_cluster
[INFO] DB initialised (SQLite (ephemeral))
[INFO] 🧹 periodic CRD cleanup started (retention=86400s, phases={'Expired', 'Denied', 'Revoked'})
[INFO] ✅ k8s-janus controller ready on cluster=gke_project_region_cluster
[INFO] 🛡️  updated janus-pod-exec ClusterRole on cluster=gke_project_region_cluster

# Engineer submits a request
[INFO] 📥 New AccessRequest [alice-debug-api] from alice@example.com → cluster=prod ns=default

# Admin approves → credentials provisioned automatically
[INFO] 🔄 [alice-debug-api] phase transition: Pending → Approved  (cluster=prod ns=default)
[INFO] 🔑 [alice-debug-api] granting access for alice@example.com on cluster=prod ns=default
[INFO] 👤 [alice-debug-api] created ServiceAccount=janus-alice-debug-api in cluster=prod ns=default
[INFO] 🔗 [alice-debug-api] created RoleBinding=janus-alice-debug-api in cluster=prod ns=default
[INFO] 🎟️  [alice-debug-api] issued token for SA=janus-alice-debug-api in cluster=prod, ttl=3600s, expires=2026-02-26T22:08:56Z
[INFO] 🔐 [alice-debug-api] stored token Secret=janus-token-alice-debug-api in ns=k8s-janus
[INFO] ✅ [alice-debug-api] access GRANTED — requester=alice@example.com cluster=prod ns=default expires=2026-02-26T22:08:56Z

# TTL expires → automatic cleanup, no manual action needed
[INFO] 🧹 [alice-debug-api] starting cleanup (TTL expired) on cluster=prod ns=default
[INFO] 🗑️  [alice-debug-api] deleted RoleBinding=janus-alice-debug-api from cluster=prod ns=default
[INFO] 🗑️  [alice-debug-api] deleted ServiceAccount=janus-alice-debug-api from cluster=prod ns=default
[INFO] 🗑️  [alice-debug-api] deleted token Secret=janus-token-alice-debug-api from ns=k8s-janus
[INFO] 💀 [alice-debug-api] marked as Expired — all credentials removed from cluster=prod ns=default

# Admin revokes an active session
[INFO] 🚫 [alice-debug-api] revoked by admin — triggering immediate cleanup on cluster=prod ns=default
[INFO] 🔒 Revoke signal sent to 1 terminal session(s) for alice-debug-api

# Hourly cleanup of old CRDs
[INFO] ✨ [periodic] cleanup done — no stale CRDs found
[INFO] 🧹 [periodic] cleanup done — deleted 3 stale terminal CRDs
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

GNU AGPL v3 License · Built with ☕ by [opsmode](https://github.com/opsmode)

</div>
