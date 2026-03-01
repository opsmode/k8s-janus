#!/usr/bin/env bash
# ⛩  K8s-Janus Setup Upload — resolves exec-based auth and uploads kubeconfig to the wizard
#
# Usage:
#   ./scripts/setup-upload.sh [--port 8080] [--kubeconfig ~/.kube/config]
#
# Requires: kubectl, python3, curl
# Optional: gcloud (for GKE), aws (for EKS), az (for AKS)

set -euo pipefail

# ==============================================================================
# Defaults & args
# ==============================================================================
PORT=8080
WIZARD_URL="http://localhost:${PORT}"
KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)       PORT="$2";            WIZARD_URL="http://localhost:${PORT}"; shift 2 ;;
    --kubeconfig) KUBECONFIG_FILE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# ==============================================================================
# Colors
# ==============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

step() { echo -e "\n${CYAN}${BOLD}━━━  $*${RESET}"; }
ok()   { echo -e "  ${GREEN}✔${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}   $*"; }
die()  { echo -e "\n  ${RED}✘  $*${RESET}\n"; exit 1; }

echo ""
echo -e "${MAGENTA}${BOLD}  ⛩   K 8 s - J A N U S   S E T U P   U P L O A D${RESET}"
echo -e "${DIM}  Resolves exec-based auth and uploads kubeconfig to the wizard${RESET}"
echo ""

# ==============================================================================
# Preflight
# ==============================================================================
step "Checking prerequisites"

for bin in kubectl python3 curl; do
  command -v "$bin" &>/dev/null && ok "$bin found" || die "$bin not found — please install it first"
done

[[ -f "$KUBECONFIG_FILE" ]] || die "kubeconfig not found: $KUBECONFIG_FILE"
ok "kubeconfig: $KUBECONFIG_FILE"

# ==============================================================================
# Check wizard is reachable
# ==============================================================================
step "Checking wizard at ${WIZARD_URL}/setup"

if ! curl -sf --max-time 3 "${WIZARD_URL}/healthz" &>/dev/null; then
  die "Wizard not reachable at ${WIZARD_URL}\n\n  Start the port-forward first:\n\n    kubectl port-forward svc/janus-webui -n k8s-janus ${PORT}:80"
fi
ok "Wizard is up"

# ==============================================================================
# Flatten kubeconfig (embed CA data)
# ==============================================================================
step "Flattening kubeconfig"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

FLAT="$TMP_DIR/flat.yaml"
KUBECONFIG="$KUBECONFIG_FILE" kubectl config view --flatten --minify=false > "$FLAT"
ok "Flattened to $FLAT"

# ==============================================================================
# Detect and resolve exec-based auth
# ==============================================================================
step "Resolving exec-based authentication"

RESOLVED="$TMP_DIR/resolved.yaml"

python3 - "$FLAT" "$RESOLVED" <<'PYEOF'
import sys, os, json, subprocess, yaml

src, dst = sys.argv[1], sys.argv[2]
kc = yaml.safe_load(open(src))
changes = 0

for u in kc.get("users", []):
    exec_cfg = u.get("user", {}).get("exec")
    if not exec_cfg:
        continue

    cmd   = exec_cfg["command"]
    args  = exec_cfg.get("args") or []
    env_overrides = {e["name"]: e["value"] for e in (exec_cfg.get("env") or [])}
    env   = {**os.environ, **env_overrides}

    print(f"  → resolving exec auth for user: {u['name']}", flush=True)
    try:
        result = subprocess.run(
            [cmd] + args, env=env,
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            print(f"    ✘ exec failed: {result.stderr.strip()}", flush=True)
            sys.exit(1)
        cred = json.loads(result.stdout)
        token = cred.get("status", {}).get("token")
        if not token:
            print("    ✘ no token in exec response", flush=True)
            sys.exit(1)
        u["user"] = {"token": token}
        changes += 1
        print(f"    ✔ token resolved", flush=True)
    except FileNotFoundError:
        print(f"    ✘ exec command not found: {cmd}", flush=True)
        print(f"      Install the auth plugin (e.g. gke-gcloud-auth-plugin) and try again.", flush=True)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"    ✘ exec timed out after 15s", flush=True)
        sys.exit(1)

with open(dst, "w") as f:
    yaml.dump(kc, f)

if changes == 0:
    print("  ℹ  No exec-based users found — kubeconfig already uses static tokens", flush=True)
else:
    print(f"  ✔ Resolved {changes} exec-based user(s)", flush=True)
PYEOF

ok "Auth resolved: $RESOLVED"

# ==============================================================================
# Upload to wizard
# ==============================================================================
step "Uploading to wizard"

RESPONSE=$(curl -sf -X POST \
  "${WIZARD_URL}/setup/upload" \
  -F "kubeconfig=@${RESOLVED}" \
  -H "Accept: application/json")

ERROR=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error') or '')" 2>/dev/null || echo "")
if [[ -n "$ERROR" ]]; then
  die "Upload failed: $ERROR"
fi

CONTEXTS=$(echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ctxs = d.get('contexts', [])
print(f'Found {len(ctxs)} context(s):')
for c in ctxs:
    print(f\"  · {c['name']}  ({c['cluster']})\")
" 2>/dev/null || echo "")

ok "Upload successful"
echo -e "${DIM}  $CONTEXTS${RESET}"

# ==============================================================================
# Open browser
# ==============================================================================
step "Opening wizard in browser"

SETUP_URL="${WIZARD_URL}/setup"

if command -v open &>/dev/null; then
  open "$SETUP_URL"
  ok "Opened $SETUP_URL"
elif command -v xdg-open &>/dev/null; then
  xdg-open "$SETUP_URL"
  ok "Opened $SETUP_URL"
else
  echo -e "\n  ${BOLD}Open this URL in your browser:${RESET}"
  echo -e "  ${CYAN}${SETUP_URL}${RESET}\n"
fi

echo ""
echo -e "${MAGENTA}${BOLD}  ⛩  Kubeconfig uploaded — complete the wizard in your browser.${RESET}"
echo ""
