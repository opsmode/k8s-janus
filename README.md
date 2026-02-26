<div align="center">

<img src="webui/static/k8s-janus-logo-blue.png" width="120" alt="K8s-Janus logo" />

# K8s-Janus

### *Just-in-Time Kubernetes Pod Access*

[![CI](https://github.com/opsmode/k8s-janus/actions/workflows/ci.yaml/badge.svg)](https://github.com/opsmode/k8s-janus/actions/workflows/ci.yaml)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Operator-326CE5?logo=kubernetes&logoColor=white)
![Helm](https://img.shields.io/badge/Helm-Chart-0F1689?logo=helm&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

**Engineers request temporary `kubectl exec` access through a web UI.**
**Admins approve with one click. The token auto-expires. No permanent permissions. Ever.**

> In Roman mythology, **Janus** was the god of doorways and transitions — watching every passage in both directions. He did not block the gate. He *governed* it.
>
> **⛩ The gate opens. Then it closes.**

<video src="https://github.com/opsmode/k8s-janus/releases/download/v0.1.7/k8s-janus.mov" controls width="100%" style="border-radius:12px;"></video>

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
         ╲▶ Denied
         (any state) ──▶ Revoked
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
| **CI/CD** | GitHub Actions · Docker · Trivy image scanning |

---

## 🔐 Security Model

| Control | Implementation |
|---------|---------------|
| 🔑 Token isolation | Token in K8s Secret — never in CRD status or logs |
| 🎯 Least privilege | Scoped RoleBinding per namespace, not ClusterRoleBinding |
| 👤 Non-root | `runAsUser: 1000`, `runAsNonRoot: true` |
| 📁 Immutable FS | `readOnlyRootFilesystem: true` |
| 🚫 No capabilities | `capabilities.drop: [ALL]` |
| 🌐 Network isolation | NetworkPolicy: egress only to K8s API |
| ⏰ TTL enforcement | Min 10 min · Max 8 hours · Enforced server-side |

---

## 🚀 Quick Start

**Prerequisites:** `kubectl` and `helm`. Optionally [`yq`](https://github.com/mikefarah/yq) to auto-patch `values.yaml`.

**Run the interactive setup script — it handles everything:**

```bash
./scripts/setup.sh
```

The script will:
1. Ask you to pick a **central cluster** (where Janus runs) and any **remote clusters** (where engineers get access)
2. Deploy the `helm-remote` agent to every selected cluster — creates the `janus-remote` ServiceAccount + RBAC
3. Deploy the main `k8s-janus` chart to the central cluster
4. Extract a static 1-year token from `janus-remote` on each cluster and store it as a kubeconfig `Secret` — no personal credentials, no cloud SDKs inside the pod
5. Auto-patch `helm/values.yaml` with the `clusters:` list (if `yq` is installed)

No cloud-specific setup, no IAM bindings, no SDKs required.

**Optional — exclude additional namespaces from the request form:**

System and GKE namespaces are excluded by default. Add any others to `helm/values.yaml`:

```yaml
janus:
  excludedNamespaces:
    - k8s-janus        # always exclude — added by default
    - kube-system      # always exclude — added by default
    - argocd
    - cert-manager
    - monitoring
    - logging
    - ingress-nginx
```

Then redeploy: `helm upgrade k8s-janus ./helm --namespace k8s-janus --reuse-values`

> **Note:** kubeconfig Secrets created by `setup.sh` are annotated with `helm.sh/resource-policy: keep` — `helm upgrade` will never overwrite them. Re-run `setup.sh` to rotate tokens.

---

<div align="center">

MIT License · Built with ☕ by [opsmode](https://github.com/opsmode)

</div>
