# Contributing to K8s-Janus

Thanks for your interest in contributing! Here's everything you need to get started.

## Development Setup

**Prerequisites:** Python 3.12, Docker, kubectl, helm

```bash
git clone https://github.com/opsmode/k8s-janus
cd k8s-janus

# Controller
cd controller && pip install -r requirements.txt

# Web UI
cd webui && pip install -r requirements.txt
APP_DIR=$(pwd) uvicorn main:app --reload --port 8000
```

For a local Kubernetes cluster, use [kind](https://kind.sigs.k8s.io/) or [k3d](https://k3d.io/).

## Making Changes

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Test locally against a real cluster using `./scripts/setup.sh`
5. Open a pull request against `main`

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add SSO integration
fix: prevent token leak in error logs
ci: update Trivy action version
docs: add multi-cluster setup guide
refactor: simplify TTL cleanup logic
```

## Pull Request Checklist

- [ ] Changes are tested against a real or local cluster
- [ ] No sensitive data (tokens, kubeconfigs) committed
- [ ] `helm/values.yaml` comments updated if new values added
- [ ] `helm/values.schema.json` is consistent with `values.yaml` (auto-generated on release)
- [ ] Commit messages follow the convention above

## Reporting Bugs

Open a [GitHub issue](https://github.com/opsmode/k8s-janus/issues) with:
- What you expected to happen
- What actually happened
- Kubernetes version and distribution
- Relevant logs from controller/webui pods

## Security Issues

See [SECURITY.md](SECURITY.md) — do not open public issues for vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the [GNU AGPL v3](LICENSE).
