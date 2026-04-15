#!/usr/bin/env bash
set -euo pipefail

# Required env vars (injected by docker run / launchd plist):
#   GITHUB_OWNER_REPO  — e.g. infroware/k8s-janus
#   GITHUB_PAT         — fine-grained PAT with Actions:Read/Write scope
#   RUNNER_NAME        — e.g. janus-runner-local (defaults to hostname)

REPO="${GITHUB_OWNER_REPO:?GITHUB_OWNER_REPO is required}"
PAT="${GITHUB_PAT:?GITHUB_PAT is required}"
NAME="${RUNNER_NAME:-$(hostname)}"
LABELS="${RUNNER_LABELS:-self-hosted,linux,x64}"

# Fetch a short-lived registration token from the GitHub API
TOKEN=$(curl -fsSL \
  -X POST \
  -H "Authorization: Bearer ${PAT}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO}/actions/runners/registration-token" \
  | jq -r .token)

# Configure the runner (non-interactive, ephemeral — re-registers on each start)
./config.sh \
  --url "https://github.com/${REPO}" \
  --token "${TOKEN}" \
  --name "${NAME}" \
  --labels "${LABELS}" \
  --unattended \
  --replace \
  --ephemeral

# Run until the job completes (ephemeral mode: one job then exit → Docker restarts)
./run.sh
