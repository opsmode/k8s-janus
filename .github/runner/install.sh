#!/usr/bin/env bash
# install.sh — start the Janus CI runner container
# Works on macOS (launchd) and Windows WSL2 (systemd or manual).
#
# Usage: bash .github/runner/install.sh <GITHUB_PAT>
set -euo pipefail

PAT="${1:?Usage: $0 <GITHUB_PAT>}"
IMAGE="infroware/k8s-janus-runner:latest"
RUNNER_NAME="${RUNNER_NAME:-janus-runner-local}"

echo "→ Pulling runner image..."
DOCKER_CONFIG=/tmp/.docker-install docker pull "${IMAGE}"

# ── macOS: register with launchd ─────────────────────────────────────────────
if [[ "$(uname -s)" == "Darwin" ]]; then
    PLIST_SRC="$(cd "$(dirname "$0")" && pwd)/com.infroware.janus-runner.plist"
    PLIST_DEST="${HOME}/Library/LaunchAgents/com.infroware.janus-runner.plist"
    echo "→ Installing launchd agent..."
    sed "s|__REPLACE_WITH_PAT__|${PAT}|g" "${PLIST_SRC}" > "${PLIST_DEST}"
    chmod 600 "${PLIST_DEST}"
    launchctl unload "${PLIST_DEST}" 2>/dev/null || true
    launchctl load "${PLIST_DEST}"
    echo "✓ Runner started. Logs: tail -f /tmp/janus-runner.log"
    exit 0
fi

# ── Linux / WSL2: run container, register as systemd service if available ────
DOCKER_CMD="docker run -d --restart=unless-stopped \\
  --name ${RUNNER_NAME} \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  -v /tmp/.buildx-cache:/tmp/.buildx-cache \\
  -e DOCKER_CONFIG=/tmp/.docker-ci \\
  -e RUNNER_ALLOW_RUNASROOT=1 \\
  -e GITHUB_OWNER_REPO=infroware/k8s-janus \\
  -e GITHUB_PAT=${PAT} \\
  -e RUNNER_NAME=${RUNNER_NAME} \\
  -e RUNNER_LABELS=self-hosted,linux,x64 \\
  ${IMAGE}"

# Stop existing container if running
docker rm -f "${RUNNER_NAME}" 2>/dev/null || true

echo "→ Starting runner container..."
eval "${DOCKER_CMD}"

# If systemd is available, install a service so the container starts on boot
if systemctl is-system-running &>/dev/null || systemctl is-system-running 2>&1 | grep -q "running\|degraded"; then
    SERVICE_FILE="/etc/systemd/system/janus-runner.service"
    echo "→ Installing systemd service..."
    sudo tee "${SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=Janus CI Runner
After=docker.service
Requires=docker.service

[Service]
Restart=always
ExecStartPre=-/usr/bin/docker rm -f ${RUNNER_NAME}
ExecStart=/usr/bin/docker run --rm \\
  --name ${RUNNER_NAME} \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  -v /tmp/.buildx-cache:/tmp/.buildx-cache \\
  -e DOCKER_CONFIG=/tmp/.docker-ci \\
  -e RUNNER_ALLOW_RUNASROOT=1 \\
  -e GITHUB_OWNER_REPO=infroware/k8s-janus \\
  -e GITHUB_PAT=${PAT} \\
  -e RUNNER_NAME=${RUNNER_NAME} \\
  -e RUNNER_LABELS=self-hosted,linux,x64 \\
  ${IMAGE}
ExecStop=/usr/bin/docker stop ${RUNNER_NAME}

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable janus-runner
    echo "✓ Runner container started and registered as systemd service."
    echo "  Logs: docker logs -f ${RUNNER_NAME}"
else
    echo "✓ Runner container started (no systemd — restart manually after reboot)."
    echo "  Logs  : docker logs -f ${RUNNER_NAME}"
    echo "  Rerun : bash $(basename "$0") ${PAT}"
fi
