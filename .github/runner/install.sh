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

echo "✓ Runner container started."
echo "  Logs  : docker logs -f ${RUNNER_NAME}"
echo "  Stop  : docker rm -f ${RUNNER_NAME}"
echo "  Rerun : bash $(basename "$0") ${PAT}"
