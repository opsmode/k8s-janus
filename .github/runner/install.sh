#!/usr/bin/env bash
# install.sh — one-time local runner setup
# Run once: bash .github/runner/install.sh <GITHUB_PAT>
set -euo pipefail

PAT="${1:?Usage: $0 <GITHUB_PAT>}"
PLIST_SRC="$(cd "$(dirname "$0")" && pwd)/com.opsmode.janus-runner.plist"
PLIST_DEST="${HOME}/Library/LaunchAgents/com.opsmode.janus-runner.plist"

echo "→ Pulling runner image..."
# Use a plain config dir to avoid macOS keychain credential helper
DOCKER_CONFIG=/tmp/.docker-install docker pull opsmode/k8s-janus-runner:latest

echo "→ Installing launchd plist..."
sed "s|__REPLACE_WITH_PAT__|${PAT}|g" "${PLIST_SRC}" > "${PLIST_DEST}"
chmod 600 "${PLIST_DEST}"

echo "→ Loading agent..."
launchctl unload "${PLIST_DEST}" 2>/dev/null || true
launchctl load "${PLIST_DEST}"

echo "✓ Runner started. Logs: tail -f /tmp/janus-runner.log"
