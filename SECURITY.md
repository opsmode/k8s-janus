# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |
| Older   | ❌        |

We support only the latest release. Please upgrade before reporting.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately by emailing: **devops@opsmode.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

You will receive a response within **48 hours**. We aim to release a fix within **7 days** for critical issues.

## Security Design

K8s-Janus is built with security as a default:

- **No permanent permissions** — all access is time-limited and auto-expires
- **Least privilege** — scoped RoleBinding per namespace, never ClusterRoleBinding
- **Token isolation** — tokens stored in K8s Secrets only, never in CRD status or logs
- **Non-root containers** — `runAsUser: 1000`, `runAsNonRoot: true`
- **Immutable filesystem** — `readOnlyRootFilesystem: true`
- **No capabilities** — `capabilities.drop: [ALL]`
- **Network isolation** — NetworkPolicy restricts egress to Kubernetes API and DNS only
- **Full audit trail** — every request, approval, command, and revocation is logged

## Disclosure Policy

We follow responsible disclosure. Once a fix is released, we will publish a security advisory on GitHub describing the vulnerability and the fix.
