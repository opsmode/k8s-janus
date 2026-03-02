#!/usr/bin/env bash
# ⛩  K8s-Janus Setup Upload — resolves exec-based auth and uploads kubeconfig to the wizard
#
# Usage:
#   bash setup-upload.sh [--port 8080] [--namespace k8s-janus] [--kubeconfig ~/.kube/config]
#                        [--management-context <context-name>]
#
# Interactively asks which context is the management cluster (where Janus is installed),
# then which contexts to include as remote clusters.
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
MGMT_CONTEXT=""
PF_PID=""
PF_STARTED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)                PORT="$2";        shift 2 ;;
    --namespace)           JANUS_NS="$2";    shift 2 ;;
    --kubeconfig)          KUBECONFIG_FILE="$2"; shift 2 ;;
    --management-context)  MGMT_CONTEXT="$2"; shift 2 ;;
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

# Read from /dev/tty so interactive prompts work even when piped through curl | bash
tty_read() {
  local prompt="$1" varname="$2"
  printf '%s' "$prompt" >/dev/tty
  read -r "$varname" </dev/tty
}

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
# List all contexts, ask which is the management cluster (for port-forward)
# ==============================================================================
step "Available contexts"

mapfile -t ALL_CONTEXTS_PRE < <(KUBECONFIG="$KUBECONFIG_FILE" kubectl config get-contexts -o name 2>/dev/null)
CURRENT_CTX_PRE=$(KUBECONFIG="$KUBECONFIG_FILE" kubectl config current-context 2>/dev/null || echo "")

[[ ${#ALL_CONTEXTS_PRE[@]} -eq 0 ]] && die "No contexts found in $KUBECONFIG_FILE"

echo ""
for i in "${!ALL_CONTEXTS_PRE[@]}"; do
  ctx="${ALL_CONTEXTS_PRE[$i]}"
  marker=""
  [[ "$ctx" == "$CURRENT_CTX_PRE" ]] && marker=" ${GREEN}← current${RESET}"
  echo -e "  ${BOLD}$((i+1))${RESET}) ${CYAN}${ctx}${RESET}${marker}"
done
echo ""

if [[ -z "$MGMT_CONTEXT" ]]; then
  if [[ ${#ALL_CONTEXTS_PRE[@]} -eq 1 ]]; then
    MGMT_CONTEXT="${ALL_CONTEXTS_PRE[0]}"
    ok "Only one context — using as management: ${MGMT_CONTEXT}"
  else
    # Pre-select the current context as default
    DEFAULT_MGMT_NUM=""
    for i in "${!ALL_CONTEXTS_PRE[@]}"; do
      [[ "${ALL_CONTEXTS_PRE[$i]}" == "$CURRENT_CTX_PRE" ]] && DEFAULT_MGMT_NUM="$((i+1))" && break
    done

    echo -e "  ${DIM}The central cluster is where Janus controller + web UI are installed.${RESET}"
    echo -e "  ${DIM}It will also be the port-forward target.${RESET}"
    echo ""
    PROMPT="  Central cluster context (enter number)"
    [[ -n "$DEFAULT_MGMT_NUM" ]] && PROMPT+=" [${DEFAULT_MGMT_NUM}]"
    PROMPT+=": "
    tty_read "$PROMPT" MGMT_NUM

    # Default to current context if user just pressed Enter
    [[ -z "$MGMT_NUM" && -n "$DEFAULT_MGMT_NUM" ]] && MGMT_NUM="$DEFAULT_MGMT_NUM"

    if [[ "$MGMT_NUM" =~ ^[0-9]+$ ]] && (( MGMT_NUM >= 1 && MGMT_NUM <= ${#ALL_CONTEXTS_PRE[@]} )); then
      MGMT_CONTEXT="${ALL_CONTEXTS_PRE[$((MGMT_NUM-1))]}"
    else
      die "Invalid selection: $MGMT_NUM"
    fi
  fi
fi

ok "Management cluster context: ${BOLD}${MGMT_CONTEXT}${RESET}"

# ==============================================================================
# Port-forward management (using the management context)
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
  KUBECONFIG="$KUBECONFIG_FILE" kubectl port-forward svc/janus-webui \
    --context "$MGMT_CONTEXT" -n "$JANUS_NS" "${PORT}:80" \
    >/dev/null 2>&1 &
  PF_PID=$!
  echo -e "  ${DIM}kubectl port-forward PID: ${PF_PID} (context: ${MGMT_CONTEXT})${RESET}"
  PF_STARTED=true

  # Register cleanup only if we started it
  trap 'stop_port_forward' EXIT

  # Wait up to 12s for it to be ready
  for i in $(seq 1 12); do
    sleep 1
    if curl -sf --max-time 2 "${WIZARD_URL}/healthz" &>/dev/null; then
      ok "Port-forward ready (PID ${PF_PID})"
      break
    fi
    if [[ $i -eq 12 ]]; then
      die "Port-forward started but wizard not responding after 12s.\n\n  Check that janus-webui is running:\n    kubectl --context ${MGMT_CONTEXT} get pods -n ${JANUS_NS}"
    fi
  done
fi

# ==============================================================================
# Let user choose which contexts to include in the upload
# ==============================================================================
step "Select contexts to upload"

TMP_DIR=$(mktemp -d)
if $PF_STARTED; then
  trap 'stop_port_forward; rm -rf "$TMP_DIR"' EXIT
else
  trap 'rm -rf "$TMP_DIR"' EXIT
fi

# Reuse ALL_CONTEXTS_PRE fetched earlier
ALL_CONTEXTS=("${ALL_CONTEXTS_PRE[@]}")

echo ""
for i in "${!ALL_CONTEXTS[@]}"; do
  ctx="${ALL_CONTEXTS[$i]}"
  marker=""
  [[ "$ctx" == "$MGMT_CONTEXT" ]] && marker=" ${CYAN}← central (management)${RESET}"
  echo -e "  ${BOLD}$((i+1))${RESET}) ${CYAN}${ctx}${RESET}${marker}"
done
echo ""

if [[ ${#ALL_CONTEXTS[@]} -eq 1 ]]; then
  SELECTED_CONTEXTS=("${ALL_CONTEXTS[@]}")
  ok "Only one context — using: ${SELECTED_CONTEXTS[0]}"
else
  echo -e "  ${DIM}Select which contexts to register with Janus (central + remotes).${RESET}"
  echo -e "  ${DIM}Enter numbers space-separated, or press Enter to include all.${RESET}"
  echo -e "  ${DIM}Example: ${BOLD}8 5 6${RESET}${DIM} → central first, then remote clusters.${RESET}"
  echo -e "  ${DIM}The central cluster context is always included automatically.${RESET}"
  echo ""
  tty_read "  Contexts to register [all]: " SELECTION

  SELECTED_CONTEXTS=()
  if [[ -z "$SELECTION" ]]; then
    SELECTED_CONTEXTS=("${ALL_CONTEXTS[@]}")
    ok "Including all ${#ALL_CONTEXTS[@]} contexts"
  else
    for num in $SELECTION; do
      if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#ALL_CONTEXTS[@]} )); then
        SELECTED_CONTEXTS+=("${ALL_CONTEXTS[$((num-1))]}")
      else
        warn "Ignoring invalid selection: $num"
      fi
    done
    [[ ${#SELECTED_CONTEXTS[@]} -eq 0 ]] && die "No valid contexts selected"
    # Always ensure management context is included
    MGMT_ALREADY=false
    for ctx in "${SELECTED_CONTEXTS[@]}"; do
      [[ "$ctx" == "$MGMT_CONTEXT" ]] && MGMT_ALREADY=true && break
    done
    if ! $MGMT_ALREADY; then
      SELECTED_CONTEXTS=("$MGMT_CONTEXT" "${SELECTED_CONTEXTS[@]}")
      warn "Management context added automatically: ${MGMT_CONTEXT}"
    fi
    ok "Selected: ${SELECTED_CONTEXTS[*]}"
  fi
fi

# ==============================================================================
# Flatten kubeconfig (embed CA data, only selected contexts)
# ==============================================================================
step "Flattening kubeconfig"

FLAT="$TMP_DIR/flat.yaml"

if [[ ${#SELECTED_CONTEXTS[@]} -eq ${#ALL_CONTEXTS[@]} ]]; then
  # All contexts — flatten the whole file
  KUBECONFIG="$KUBECONFIG_FILE" kubectl config view --flatten --minify=false > "$FLAT"
else
  # Flatten each selected context individually then merge
  PARTS=()
  for ctx in "${SELECTED_CONTEXTS[@]}"; do
    part="$TMP_DIR/ctx-${ctx//\//_}.yaml"
    KUBECONFIG="$KUBECONFIG_FILE" kubectl config view --flatten --minify \
      --context "$ctx" > "$part"
    PARTS+=("$part")
  done

  # Merge all parts by concatenating (kubectl supports KUBECONFIG=a:b:c view --flatten)
  MERGED_KUBECONFIG=$(IFS=":"; echo "${PARTS[*]}")
  KUBECONFIG="$MERGED_KUBECONFIG" kubectl config view --flatten --minify=false > "$FLAT"
fi

ok "Flattened (${#SELECTED_CONTEXTS[@]} context(s))"

# ==============================================================================
# Detect and resolve exec-based auth
# ==============================================================================
step "Resolving exec-based authentication"

RESOLVED="$TMP_DIR/resolved.yaml"

python3 - "$FLAT" "$RESOLVED" "$TMP_DIR" <<'PYEOF'
import sys, os, json, subprocess

src, dst, tmp = sys.argv[1], sys.argv[2], sys.argv[3]

# ensure pyyaml available — use a temp venv to avoid PEP 668 / externally-managed errors
try:
    import yaml
except ImportError:
    venv_dir = os.path.join(tmp, "venv")
    subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
    pip = os.path.join(venv_dir, "bin", "pip")
    subprocess.run([pip, "install", "--quiet", "pyyaml"], check=True)
    sys.path.insert(0, os.path.join(venv_dir, "lib",
        next(d for d in os.listdir(os.path.join(venv_dir, "lib")) if d.startswith("python")),
        "site-packages"))
    import yaml
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
