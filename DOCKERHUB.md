<img src="https://raw.githubusercontent.com/infroware/k8s-janus/main/webui/static/k8s-janus-logo-readme.png" width="80" alt="K8s-Janus" />

## K8s-Janus — Just-in-Time Kubernetes Pod Access

Engineers request temporary `kubectl exec` access through a web UI. Admins approve with one click. The token auto-expires. No permanent permissions. Ever.

---

### Features

- **Web terminal** — browser-based `kubectl exec` shell, no local kubeconfig needed
- **Split-pane terminal** — two pods side-by-side in one browser tab
- **Pod logs & events** — view real-time logs and K8s events from the terminal sidebar
- **Quick commands** — personal per-cluster command palette, saved and replayed with one click
- **Multi-cluster** — manage access to any number of remote clusters from one central install
- **Multi-namespace** — single request covers multiple namespaces, namespace tab strip in terminal
- **One-click approval** — admins approve, deny, or override TTL from the dashboard
- **Instant revoke** — terminate any active session immediately
- **Pending auto-expiry** — auto-deny requests that go unapproved past a configurable limit
- **Native OIDC/SSO** — Google, GitHub, Entra ID, Okta, GitLab, or any OIDC provider. No oauth2-proxy required.
- **Full audit trail** — every request event, session open/close, command, idle timeout, and revocation logged
- **PostgreSQL backend** — optional persistent history that survives pod restarts
- **Security hardened** — non-root, read-only FS, all capabilities dropped, NetworkPolicy

### Images

| Image | Description |
|-------|-------------|
| `infroware/k8s-janus-webui` | FastAPI web UI + xterm.js terminal |
| `infroware/k8s-janus-controller` | kopf Kubernetes operator |

### Quick start

```bash
helm repo add k8s-janus https://infroware.github.io/k8s-janus
helm repo update
helm upgrade --install k8s-janus k8s-janus/k8s-janus \
  --namespace k8s-janus --create-namespace
```

### Links

https://github.com/infroware/k8s-janus
