#!/usr/bin/env bash
# install.sh — set up a native GitHub Actions self-hosted runner on WSL2 (Ubuntu)
#
# Usage:
#   bash .github/runner/install.sh <GITHUB_PAT>
#
# The PAT needs: repo → Actions (read/write)
# Get one at: github.com → Settings → Developer settings → Fine-grained tokens
#
# Requirements: WSL2 with Ubuntu 22.04/24.04, systemd enabled.
# Enable systemd in WSL2 if not already:
#   echo -e "[boot]\nsystemd=true" | sudo tee /etc/wsl.conf
#   wsl.exe --shutdown   (then reopen WSL2)

set -euo pipefail

PAT="${1:?Usage: $0 <GITHUB_PAT>}"

REPO="infroware/k8s-janus"
RUNNER_VERSION="2.323.0"
RUNNER_DIR="${HOME}/actions-runner"
RUNNER_NAME="${RUNNER_NAME:-$(hostname)-wsl2}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,linux,x64}"
YQ_VERSION="v4.44.6"

echo "==> Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    ca-certificates curl git openssh-client gnupg \
    python3 python3-pip jq unzip

echo "==> Installing Docker CE + buildx..."
if ! command -v docker &>/dev/null; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends docker-ce docker-ce-cli docker-buildx-plugin
    sudo usermod -aG docker "$USER"
    echo "   NOTE: re-login (or run 'newgrp docker') for group membership to take effect."
else
    echo "   Docker already installed, skipping."
fi

echo "==> Installing Helm..."
if ! command -v helm &>/dev/null; then
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
else
    echo "   Helm already installed, skipping."
fi

echo "==> Installing yq ${YQ_VERSION}..."
if ! command -v yq &>/dev/null; then
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    sudo curl -fsSL \
        "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${ARCH}" \
        -o /usr/local/bin/yq
    sudo chmod +x /usr/local/bin/yq
else
    echo "   yq already installed, skipping."
fi

echo "==> Installing Python dependencies..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
pip3 install --break-system-packages --root-user-action=ignore --quiet \
    -r "${REPO_ROOT}/controller/requirements.txt" \
    -r "${REPO_ROOT}/webui/requirements.txt" \
    flake8

echo "==> Baking GitHub known hosts..."
mkdir -p "${HOME}/.ssh" && chmod 700 "${HOME}/.ssh"
ssh-keyscan -t ed25519,rsa github.com >> "${HOME}/.ssh/known_hosts" 2>/dev/null
sort -u "${HOME}/.ssh/known_hosts" -o "${HOME}/.ssh/known_hosts"
chmod 600 "${HOME}/.ssh/known_hosts"

echo "==> Downloading GitHub Actions runner v${RUNNER_VERSION}..."
mkdir -p "${RUNNER_DIR}"
ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/')
curl -fsSL \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${ARCH}-${RUNNER_VERSION}.tar.gz" \
    | tar -xz -C "${RUNNER_DIR}"

echo "==> Fetching runner registration token..."
REG_TOKEN=$(curl -fsSL \
    -X POST \
    -H "Authorization: Bearer ${PAT}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}/actions/runners/registration-token" \
    | jq -r .token)

echo "==> Configuring runner..."
cd "${RUNNER_DIR}"
./config.sh \
    --url "https://github.com/${REPO}" \
    --token "${REG_TOKEN}" \
    --name "${RUNNER_NAME}" \
    --labels "${RUNNER_LABELS}" \
    --unattended \
    --replace

echo "==> Installing as systemd service..."
sudo "${RUNNER_DIR}/svc.sh" install "$USER"
sudo "${RUNNER_DIR}/svc.sh" start

echo ""
echo "✓ Runner '${RUNNER_NAME}' is running as a systemd service."
echo ""
echo "  Status : sudo ${RUNNER_DIR}/svc.sh status"
echo "  Logs   : journalctl -u actions.runner.${REPO//\//.}.${RUNNER_NAME} -f"
echo "  Stop   : sudo ${RUNNER_DIR}/svc.sh stop"
echo "  Remove : sudo ${RUNNER_DIR}/svc.sh uninstall && ${RUNNER_DIR}/config.sh remove --token <token>"
