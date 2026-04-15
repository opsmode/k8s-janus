# Self-hosted CI Runner (WSL2 native)

Native GitHub Actions runner for `infroware/k8s-janus` CI — runs directly on WSL2, no Docker container overhead.

## Prerequisites

- WSL2 with Ubuntu 22.04 or 24.04
- systemd enabled:
  ```
  echo -e "[boot]\nsystemd=true" | sudo tee /etc/wsl.conf
  wsl.exe --shutdown
  ```

## Install

```bash
bash .github/runner/install.sh <GITHUB_PAT>
```

Get a PAT at: **github.com → Settings → Developer settings → Fine-grained tokens**  
Required scope: `infroware/k8s-janus` → Actions (read/write)

The script installs: Docker CE, Helm, yq, Python deps, flake8, the runner binary, and registers it as a systemd service.

## What's installed

| Tool | Purpose |
|------|---------|
| Docker CE + buildx | `docker/build-push-action` in CI |
| Helm | `helm lint` in CI |
| yq | Helm values patching in release workflow |
| Python deps + flake8 | Tests and linting |
| GitHub known hosts | `ssh-keyscan` baked in — no runtime delay |

## Manage the service

```bash
# Status
sudo ~/actions-runner/svc.sh status

# Logs
journalctl -u actions.runner.infroware.k8s-janus.<runner-name> -f

# Stop / start
sudo ~/actions-runner/svc.sh stop
sudo ~/actions-runner/svc.sh start

# Remove
sudo ~/actions-runner/svc.sh uninstall
~/actions-runner/config.sh remove --token <removal-token>
```

## Re-run after WSL2 restart

The systemd service starts automatically on WSL2 boot (when systemd is enabled).
