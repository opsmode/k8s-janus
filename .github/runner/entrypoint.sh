#!/usr/bin/env bash
set -euo pipefail

# Env vars:
#   GITHUB_OWNER_REPO — e.g. infroware/k8s-janus  (required)
#   RUNNER_TOKEN      — registration token from GitHub UI (preferred, valid 1h)
#   GITHUB_PAT        — PAT with administration:write, used to auto-fetch token
#   RUNNER_NAME       — defaults to hostname
#   RUNNER_LABELS     — defaults to self-hosted,linux,x64

REPO="${GITHUB_OWNER_REPO:?GITHUB_OWNER_REPO is required}"
NAME="${RUNNER_NAME:-$(hostname)}"
LABELS="${RUNNER_LABELS:-self-hosted,linux,x64}"

# Only configure if not already registered
if [ ! -f ".credentials" ]; then
  if [ -n "${RUNNER_TOKEN:-}" ]; then
    TOKEN="${RUNNER_TOKEN}"
  elif [ -n "${GITHUB_PAT:-}" ]; then
    TOKEN=$(curl -fsSL \
      -X POST \
      -H "Authorization: Bearer ${GITHUB_PAT}" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${REPO}/actions/runners/registration-token" \
      | jq -r .token)
  else
    echo "ERROR: set RUNNER_TOKEN (from GitHub UI) or GITHUB_PAT" >&2
    exit 1
  fi

  ./config.sh \
    --url "https://github.com/${REPO}" \
    --token "${TOKEN}" \
    --name "${NAME}" \
    --labels "${LABELS}" \
    --unattended \
    --replace
fi

./run.sh
