# K8s-Janus Roadmap

## In Progress / Next

See open issues and PRs on GitHub.

---

## Backlog

### Access Control
- **Read-only access mode** — `pods/log` + `events` only, no exec shell. For auditors/observers who shouldn't be able to modify containers.
- **Pod selector restrictions** — scope access to pods matching a label selector (e.g. `app=payment`) rather than all pods in a namespace.
- **Custom ClusterRole selection** — choose at request time between exec, read-only, port-forward, etc. instead of always getting `janus-pod-exec`.
- **Cross-cluster request** — single request spanning the same namespace across multiple clusters.
- **Group/team-based policies** — define "team platform can always access namespace infra" without per-request approval.

### Approval Workflow
- **Approval workflow policies** — require quorum (e.g. 2-of-3 approvers), approval time windows, or escalation paths for on-call rotation.
- **Approval delegation** — temporary admin stand-in mode for cover during OOO/vacation.
- **Approval reason field** — capture why access was approved (mirrors deny reason). Audit completeness.
- **Scheduled/advance requests** — pre-request access for a known maintenance window; auto-activates at scheduled time.

### Audit & Compliance
- **Session recording** — save full terminal transcript to audit log with replay capability.
- **Structured audit export** — ship audit events to SIEM/Splunk/Datadog via HTTP webhook or Kafka topic.
- **Anomaly detection** — alert on unusual patterns (off-hours access, bulk namespace requests, dangerous commands).

### Observability
- **Prometheus metrics** — `/metrics` endpoint: request rate, approval latency, active sessions, TTL histogram, per-cluster breakdown.
- **Admin dashboard search/filter** — filter requests by cluster, requester, status, date range.
- **Bulk admin actions** — revoke/deny multiple requests in one click.

### Integrations
- **Generic outbound webhook** — HTTP callback on every state change (Pending→Approved, Active→Expired, etc.). Covers any downstream integration.
- **OIDC/SAML direct support** — built-in auth without requiring an external oauth2-proxy in front.
- **Dynamic admin management** — UI to add/remove admin emails without pod restart.

---

## Won't Do (by design)

- **Permanent access grants** — antithetical to JIT model.
- **kubectl install in browser** — terminal is browser-native WebSocket exec, no local tooling needed.
