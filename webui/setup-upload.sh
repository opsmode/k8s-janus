#!/usr/bin/env bash
# ⛩  K8s-Janus Setup Upload — resolves exec-based auth and uploads kubeconfig to the wizard
#
# Usage:
#   bash setup-upload.sh [--port 8080] [--namespace k8s-janus] [--kubeconfig ~/.kube/config]
#                        [--management-context <context-name>]
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
    --port)                PORT="$2";             shift 2 ;;
    --namespace)           JANUS_NS="$2";         shift 2 ;;
    --kubeconfig)          KUBECONFIG_FILE="$2";  shift 2 ;;
    --management-context)  MGMT_CONTEXT="$2";     shift 2 ;;
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

# Read from /dev/tty so prompts work even when piped through curl | bash
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
# List contexts — pick central cluster
# ==============================================================================
step "Available contexts"

mapfile -t ALL_CONTEXTS < <(KUBECONFIG="$KUBECONFIG_FILE" kubectl config get-contexts -o name 2>/dev/null)
CURRENT_CTX=$(KUBECONFIG="$KUBECONFIG_FILE" kubectl config current-context 2>/dev/null || echo "")

[[ ${#ALL_CONTEXTS[@]} -eq 0 ]] && die "No contexts found in $KUBECONFIG_FILE"

echo ""
for i in "${!ALL_CONTEXTS[@]}"; do
  marker=""
  [[ "${ALL_CONTEXTS[$i]}" == "$CURRENT_CTX" ]] && marker=" ${GREEN}← current${RESET}"
  echo -e "  ${BOLD}$((i+1))${RESET}) ${CYAN}${ALL_CONTEXTS[$i]}${RESET}${marker}"
done
echo ""

if [[ -z "$MGMT_CONTEXT" ]]; then
  if [[ ${#ALL_CONTEXTS[@]} -eq 1 ]]; then
    MGMT_CONTEXT="${ALL_CONTEXTS[0]}"
    ok "Only one context — using as central: ${MGMT_CONTEXT}"
  else
    DEFAULT_NUM=""
    for i in "${!ALL_CONTEXTS[@]}"; do
      [[ "${ALL_CONTEXTS[$i]}" == "$CURRENT_CTX" ]] && DEFAULT_NUM="$((i+1))" && break
    done
    echo -e "  ${DIM}The central cluster is where the Janus controller + web UI are installed.${RESET}"
    PROMPT="  Central cluster"
    [[ -n "$DEFAULT_NUM" ]] && PROMPT+=" [${DEFAULT_NUM}]"
    PROMPT+=": "
    tty_read "$PROMPT" MGMT_NUM
    [[ -z "$MGMT_NUM" && -n "$DEFAULT_NUM" ]] && MGMT_NUM="$DEFAULT_NUM"
    if [[ "$MGMT_NUM" =~ ^[0-9]+$ ]] && (( MGMT_NUM >= 1 && MGMT_NUM <= ${#ALL_CONTEXTS[@]} )); then
      MGMT_CONTEXT="${ALL_CONTEXTS[$((MGMT_NUM-1))]}"
    else
      die "Invalid selection: $MGMT_NUM"
    fi
  fi
fi

ok "Central cluster: ${BOLD}${MGMT_CONTEXT}${RESET}"

# ==============================================================================
# Port-forward (using the central context)
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
  trap 'stop_port_forward' EXIT

  for i in $(seq 1 12); do
    sleep 1
    if curl -sf --max-time 2 "${WIZARD_URL}/healthz" &>/dev/null; then
      ok "Port-forward ready (PID ${PF_PID})"
      break
    fi
    if [[ $i -eq 12 ]]; then
      die "Port-forward not responding after 12s.\n\n  Check janus-webui is running:\n    kubectl --context ${MGMT_CONTEXT} get pods -n ${JANUS_NS}"
    fi
  done
fi

# ==============================================================================
# Select which contexts to include in the upload
# ==============================================================================
step "Select contexts to upload"

TMP_DIR=$(mktemp -d)
if $PF_STARTED; then
  trap 'stop_port_forward; rm -rf "$TMP_DIR"' EXIT
else
  trap 'rm -rf "$TMP_DIR"' EXIT
fi

echo ""
for i in "${!ALL_CONTEXTS[@]}"; do
  marker=""
  [[ "${ALL_CONTEXTS[$i]}" == "$MGMT_CONTEXT" ]] && marker=" ${CYAN}← central${RESET}"
  echo -e "  ${BOLD}$((i+1))${RESET}) ${CYAN}${ALL_CONTEXTS[$i]}${RESET}${marker}"
done
echo ""

SELECTED_CONTEXTS=()
if [[ ${#ALL_CONTEXTS[@]} -eq 1 ]]; then
  SELECTED_CONTEXTS=("${ALL_CONTEXTS[@]}")
  ok "Only one context — using: ${SELECTED_CONTEXTS[0]}"
else
  echo -e "  ${DIM}Enter numbers space-separated, or press Enter to include all.${RESET}"
  tty_read "  Contexts to register [all]: " SELECTION

  if [[ -z "$SELECTION" ]]; then
    SELECTED_CONTEXTS=("${ALL_CONTEXTS[@]}")
    ok "Including all ${#ALL_CONTEXTS[@]} contexts"
  else
    for num in $SELECTION; do
      if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#ALL_CONTEXTS[@]} )); then
        SELECTED_CONTEXTS+=("${ALL_CONTEXTS[$((num-1))]}")
      else
        warn "Ignoring invalid: $num"
      fi
    done
    [[ ${#SELECTED_CONTEXTS[@]} -eq 0 ]] && die "No valid contexts selected"
    # Always include central
    MGMT_ALREADY=false
    for ctx in "${SELECTED_CONTEXTS[@]}"; do
      [[ "$ctx" == "$MGMT_CONTEXT" ]] && MGMT_ALREADY=true && break
    done
    if ! $MGMT_ALREADY; then
      SELECTED_CONTEXTS=("$MGMT_CONTEXT" "${SELECTED_CONTEXTS[@]}")
      warn "Central context added automatically: ${MGMT_CONTEXT}"
    fi
    ok "Selected ${#SELECTED_CONTEXTS[@]} context(s)"
  fi
fi

# ==============================================================================
# Flatten kubeconfig (embed CA data, only selected contexts)
# ==============================================================================
step "Flattening kubeconfig"

FLAT="$TMP_DIR/flat.yaml"

if [[ ${#SELECTED_CONTEXTS[@]} -eq ${#ALL_CONTEXTS[@]} ]]; then
  KUBECONFIG="$KUBECONFIG_FILE" kubectl config view --flatten --minify=false > "$FLAT"
else
  PARTS=()
  for ctx in "${SELECTED_CONTEXTS[@]}"; do
    part="$TMP_DIR/ctx-${ctx//\//_}.yaml"
    KUBECONFIG="$KUBECONFIG_FILE" kubectl config view --flatten --minify --context "$ctx" > "$part"
    PARTS+=("$part")
  done
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
CONTEXTS_JSON=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('contexts',[])))" 2>/dev/null || echo "[]")

# ==============================================================================
# CLI or browser?
# ==============================================================================
step "How would you like to continue?"

echo ""
echo -e "  ${BOLD}1)${RESET} ${GREEN}CLI${RESET}      — run setup now in this terminal (no browser needed)"
echo -e "  ${BOLD}2)${RESET} ${CYAN}Browser${RESET}  — open the web wizard to select clusters and watch progress"
echo ""
tty_read "  Choice [1]: " MODE_CHOICE
[[ -z "$MODE_CHOICE" ]] && MODE_CHOICE="1"

SETUP_URL="${WIZARD_URL}/setup${SESSION_ID:+?session=${SESSION_ID}}"

if [[ "$MODE_CHOICE" == "2" ]]; then
  # ── Browser mode ──────────────────────────────────────────────────────────
  step "Opening wizard in browser"
  if command -v open &>/dev/null; then
    open "$SETUP_URL" && ok "Opened $SETUP_URL"
  elif command -v xdg-open &>/dev/null; then
    xdg-open "$SETUP_URL" && ok "Opened $SETUP_URL"
  else
    echo -e "\n  ${BOLD}Open this URL in your browser:${RESET}"
    echo -e "  ${CYAN}${SETUP_URL}${RESET}"
  fi

  echo ""
  echo -e "${MAGENTA}${BOLD}  ⛩  Kubeconfig uploaded — complete the wizard in your browser.${RESET}"
  echo ""

  if $PF_STARTED; then
    echo -e "  ${DIM}Port-forward running (PID ${PF_PID}) — press ${RESET}${BOLD}Ctrl+C${DIM} when done.${RESET}"
    trap 'echo ""; stop_port_forward; ok "Port-forward stopped"; exit 0' INT TERM
    elapsed=0
    while kill -0 "$PF_PID" 2>/dev/null; do
      sleep 5; elapsed=$((elapsed + 5))
      (( elapsed % 30 == 0 )) && echo -e "  ${DIM}… port-forward still running (${elapsed}s)${RESET}"
    done
    ok "Port-forward exited"
  else
    echo -e "  ${DIM}Stop port-forward when done: ${RESET}${BOLD}pkill -f 'port-forward svc/janus-webui'${RESET}"
  fi

else
  # ── CLI mode ───────────────────────────────────────────────────────────────
  mapfile -t CTX_NAMES < <(echo "$CONTEXTS_JSON" | python3 -c "
import sys, json
for c in json.load(sys.stdin):
    print(c['name'])
")

  [[ ${#CTX_NAMES[@]} -eq 0 ]] && die "No contexts available from uploaded kubeconfig"

  echo ""
  for i in "${!CTX_NAMES[@]}"; do
    marker=""
    [[ "${CTX_NAMES[$i]}" == "$MGMT_CONTEXT" ]] && marker=" ${CYAN}← central${RESET}"
    echo -e "  ${BOLD}$((i+1))${RESET}) ${CYAN}${CTX_NAMES[$i]}${RESET}${marker}"
  done
  echo ""

  # Central context
  DEFAULT_CENTRAL=""
  for i in "${!CTX_NAMES[@]}"; do
    [[ "${CTX_NAMES[$i]}" == "$MGMT_CONTEXT" ]] && DEFAULT_CENTRAL="$((i+1))" && break
  done
  PROMPT="  Central cluster"
  [[ -n "$DEFAULT_CENTRAL" ]] && PROMPT+=" [${DEFAULT_CENTRAL}]"
  PROMPT+=": "
  tty_read "$PROMPT" CENTRAL_NUM
  [[ -z "$CENTRAL_NUM" && -n "$DEFAULT_CENTRAL" ]] && CENTRAL_NUM="$DEFAULT_CENTRAL"
  if [[ "$CENTRAL_NUM" =~ ^[0-9]+$ ]] && (( CENTRAL_NUM >= 1 && CENTRAL_NUM <= ${#CTX_NAMES[@]} )); then
    CENTRAL_CTX="${CTX_NAMES[$((CENTRAL_NUM-1))]}"
  else
    die "Invalid selection: $CENTRAL_NUM"
  fi
  ok "Central: ${CENTRAL_CTX}"

  # Remote contexts
  echo ""
  echo -e "  ${DIM}Enter remote cluster numbers (space-separated), or Enter to skip.${RESET}"
  tty_read "  Remote clusters: " REMOTE_NUMS
  REMOTE_CTXS=()
  for num in $REMOTE_NUMS; do
    if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#CTX_NAMES[@]} )); then
      REMOTE_CTXS+=("${CTX_NAMES[$((num-1))]}")
    else
      warn "Ignoring invalid: $num"
    fi
  done

  # Build JSON payload
  CENTRAL_JSON=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$CENTRAL_CTX")
  REMOTE_JSON="["
  for ctx in "${REMOTE_CTXS[@]}"; do
    REMOTE_JSON+=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$ctx")","
  done
  REMOTE_JSON="${REMOTE_JSON%,}]"

  RUN_PAYLOAD="{\"session_id\":\"${SESSION_ID}\",\"central_context\":${CENTRAL_JSON},\"remote_contexts\":${REMOTE_JSON}}"

  step "Running setup"
  RUN_RESP=$(curl -sf -X POST "${WIZARD_URL}/setup/run" \
    -H "Content-Type: application/json" \
    -d "$RUN_PAYLOAD" 2>&1) || die "Failed to start setup: $RUN_RESP"

  RUN_ERR=$(echo "$RUN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error') or '')" 2>/dev/null || echo "")
  [[ -n "$RUN_ERR" ]] && die "Setup failed to start: $RUN_ERR"

  # Stream progress via WebSocket
  echo ""
  python3 - "${WIZARD_URL/http/ws}/ws/setup/${SESSION_ID}" <<'WSEOF'
import sys, asyncio

async def stream(url):
    try:
        import websockets
    except ImportError:
        print("  [INFO] websockets not available — watching via HTTP poll")
        import urllib.request, json, time
        base = url.replace("ws://","http://").replace("wss://","https://")
        base = base.replace("/ws/setup/", "/setup/status/")
        for _ in range(360):
            try:
                r = urllib.request.urlopen(base, timeout=5)
                data = json.loads(r.read())
                for line in data.get("lines", []):
                    print(f"  {line}")
                if data.get("done"):
                    break
            except Exception:
                pass
            time.sleep(2)
        return

    GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"
    CYAN="\033[0;36m"; BOLD="\033[1m"; RESET="\033[0m"

    async with websockets.connect(url) as ws:
        async for msg in ws:
            import json as _json
            try:
                d = _json.loads(msg)
            except Exception:
                print(f"  {msg}")
                continue
            text = d.get("text","")
            if text.startswith("[OK]"):
                print(f"  {GREEN}{BOLD}{text}{RESET}")
            elif text.startswith("[ERROR]") or text.startswith("[FATAL]"):
                print(f"  {RED}{BOLD}{text}{RESET}")
            elif text.startswith("[WARN]"):
                print(f"  {YELLOW}{text}{RESET}")
            elif text.startswith("[DONE]"):
                print(f"  {GREEN}{BOLD}{text}{RESET}")
            else:
                print(f"  {CYAN}{text}{RESET}")
            sys.stdout.flush()
            if d.get("type") == "done":
                break

asyncio.run(stream(sys.argv[1]))
WSEOF

  echo ""
  stop_port_forward
  echo -e "\n${MAGENTA}${BOLD}  ⛩  Setup complete.${RESET}"
fi
echo ""
