#!/usr/bin/env bash
# ⛩  K8s-Janus Setup Upload — resolves exec-based auth and uploads kubeconfig to the wizard
#
# Usage:
#   bash setup-upload.sh [--port 8080] [--namespace k8s-janus] [--kubeconfig ~/.kube/config]
#
# Requires: kubectl, python3, curl
# Optional: gcloud (for GKE), aws (for EKS), az (for AKS)

set -euo pipefail

# ==============================================================================
# Defaults & args
# ==============================================================================
PORT=8080
JANUS_NS="k8s-janus"
KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"
PF_PID=""
PF_STARTED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)        PORT="$2";          shift 2 ;;
    --namespace)   JANUS_NS="$2";      shift 2 ;;
    --kubeconfig)  KUBECONFIG_FILE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

WIZARD_URL="http://localhost:${PORT}"

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
# Port-forward management
# ==============================================================================
step "Checking wizard at ${WIZARD_URL}"

stop_port_forward() {
  if [[ -n "$PF_PID" ]] && kill -0 "$PF_PID" 2>/dev/null; then
    kill "$PF_PID" 2>/dev/null || true
  fi
}

if curl -sf --max-time 2 "${WIZARD_URL}/healthz" &>/dev/null; then
  ok "Wizard already reachable — reusing existing port-forward"
else
  warn "Wizard not reachable — starting port-forward in background"
  kubectl port-forward svc/janus-webui -n "$JANUS_NS" "${PORT}:80" \
    >/dev/null 2>&1 &
  PF_PID=$!
  echo -e "  ${DIM}kubectl port-forward PID: ${PF_PID}${RESET}"
  PF_STARTED=true

  # Register cleanup only if we started it
  trap 'stop_port_forward' EXIT

  # Wait up to 8s for it to be ready
  for i in $(seq 1 8); do
    sleep 1
    if curl -sf --max-time 2 "${WIZARD_URL}/healthz" &>/dev/null; then
      ok "Port-forward ready (PID ${PF_PID})"
      break
    fi
    if [[ $i -eq 8 ]]; then
      die "Port-forward started but wizard not responding after 8s.\n\n  Check that janus-webui is running:\n    kubectl get pods -n ${JANUS_NS}"
    fi
  done
fi

# ==============================================================================
# Flatten kubeconfig (embed CA data)
# ==============================================================================
step "Flattening kubeconfig"

TMP_DIR=$(mktemp -d)
# Extend trap to also clean tmp dir
if $PF_STARTED; then
  trap 'stop_port_forward; rm -rf "$TMP_DIR"' EXIT
else
  trap 'rm -rf "$TMP_DIR"' EXIT
fi

FLAT="$TMP_DIR/flat.yaml"
KUBECONFIG="$KUBECONFIG_FILE" kubectl config view --flatten --minify=false > "$FLAT"
ok "Flattened"

# ==============================================================================
# Detect and resolve exec-based auth
# ==============================================================================
step "Resolving exec-based authentication"

RESOLVED="$TMP_DIR/resolved.yaml"

python3 - "$FLAT" "$RESOLVED" <<'PYEOF'
import sys, os, json, subprocess

# ensure pyyaml available (system python may not have it)
try:
    import yaml
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--user", "pyyaml"],
                   check=True)
    import yaml

src, dst = sys.argv[1], sys.argv[2]
kc = yaml.safe_load(open(src))
changes = 0

for u in kc.get("users", []):
    exec_cfg = u.get("user", {}).get("exec")
    if not exec_cfg:
        continue

    cmd  = exec_cfg["command"]
    args = exec_cfg.get("args") or []
    env  = {**os.environ, **{e["name"]: e["value"] for e in (exec_cfg.get("env") or [])}}

    print(f"  → resolving exec auth for user: {u['name']}", flush=True)
    try:
        result = subprocess.run([cmd] + args, env=env,
                                capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            print(f"    ✘ exec failed: {result.stderr.strip()}", flush=True)
            sys.exit(1)
        cred  = json.loads(result.stdout)
        token = cred.get("status", {}).get("token")
        if not token:
            print("    ✘ no token in exec response", flush=True)
            sys.exit(1)
        u["user"] = {"token": token}
        changes += 1
        print("    ✔ token resolved", flush=True)
    except FileNotFoundError:
        print(f"    ✘ exec command not found: {cmd}", flush=True)
        print("      Install the auth plugin (e.g. gke-gcloud-auth-plugin) and try again.", flush=True)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("    ✘ exec timed out after 15s", flush=True)
        sys.exit(1)

with open(dst, "w") as f:
    yaml.dump(kc, f)

if changes == 0:
    print("  ℹ  No exec-based users — kubeconfig already uses static tokens", flush=True)
else:
    print(f"  ✔ Resolved {changes} exec-based user(s)", flush=True)
PYEOF

ok "Auth resolved"

# ==============================================================================
# Upload to wizard
# ==============================================================================
step "Uploading to wizard"

RESPONSE=$(curl -sf -X POST \
  "${WIZARD_URL}/setup/upload" \
  -F "kubeconfig=@${RESOLVED}" \
  -H "Accept: application/json")

ERROR=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error') or '')" 2>/dev/null || echo "")
[[ -n "$ERROR" ]] && die "Upload failed: $ERROR"

echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ctxs = d.get('contexts', [])
print(f'  Found {len(ctxs)} context(s):')
for c in ctxs:
    print(f\"    · {c['name']}  ({c['cluster']})\")
" 2>/dev/null || true

ok "Upload successful"

SESSION_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null || echo "")

# ==============================================================================
# Open browser
# ==============================================================================
step "Opening wizard in browser"

SETUP_URL="${WIZARD_URL}/setup${SESSION_ID:+?session=${SESSION_ID}}"

if command -v open &>/dev/null; then
  open "$SETUP_URL" && ok "Opened $SETUP_URL"
elif command -v xdg-open &>/dev/null; then
  xdg-open "$SETUP_URL" && ok "Opened $SETUP_URL"
else
  echo -e "\n  ${BOLD}Open this URL in your browser:${RESET}"
  echo -e "  ${CYAN}${SETUP_URL}${RESET}"
fi

# ==============================================================================
# Wait for wizard completion, then clean up
# ==============================================================================
echo ""
echo -e "${MAGENTA}${BOLD}  ⛩  Kubeconfig uploaded — complete the wizard in your browser.${RESET}"
echo ""

if $PF_STARTED; then
  echo -e "  ${BOLD}Port-forward running in background (PID ${PF_PID}).${RESET}"
  echo -e "  ${DIM}Complete the wizard in your browser, then press ${RESET}${BOLD}Ctrl+C${DIM} to stop.${RESET}"
  echo -e "  ${DIM}Or stop it later with:  ${RESET}${BOLD}kill ${PF_PID}${RESET}"
  echo ""

  trap 'echo ""; stop_port_forward; ok "Port-forward stopped"; exit 0' INT TERM

  # Keep alive — print a heartbeat every 30s so user knows it's still running
  elapsed=0
  while kill -0 "$PF_PID" 2>/dev/null; do
    sleep 5
    elapsed=$((elapsed + 5))
    if (( elapsed % 30 == 0 )); then
      echo -e "  ${DIM}… port-forward still running (${elapsed}s) — Ctrl+C to stop${RESET}"
    fi
  done
  ok "Port-forward exited"
else
  echo -e "  ${DIM}Port-forward was already running — stop it when done with:${RESET}"
  echo -e "  ${BOLD}pkill -f 'port-forward svc/janus-webui'${RESET}"
fi
echo ""
