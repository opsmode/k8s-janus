# CI Runner Image

Pre-baked runner image for `opsmode/k8s-janus` CI. Eliminates per-job install overhead.

## What's baked in

- Python 3 + all deps from `controller/requirements.txt` + `webui/requirements.txt` + `flake8`
- Docker CLI + buildx plugin
- Helm 3
- yq (latest stable)
- GitHub known hosts for `github.com` (no `ssh-keyscan` at runtime)

## Rebuild

Automatically rebuilt by `.github/workflows/runner-image.yaml` on any change to:
- This Dockerfile
- `controller/requirements.txt`
- `webui/requirements.txt`

Or trigger manually via `workflow_dispatch`.

## Register a self-hosted runner using this image

```bash
docker run -d --restart=unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e RUNNER_URL=https://github.com/opsmode/k8s-janus \
  -e RUNNER_TOKEN=<token-from-github-settings> \
  -e RUNNER_NAME=janus-runner-1 \
  -e RUNNER_LABELS=self-hosted \
  opsmode/k8s-janus-runner:latest \
  bash -c "/opt/config.sh --url \$RUNNER_URL --token \$RUNNER_TOKEN --name \$RUNNER_NAME --labels \$RUNNER_LABELS --unattended && /opt/run.sh"
```

Get the token from: `github.com/opsmode/k8s-janus → Settings → Actions → Runners → New self-hosted runner`.
