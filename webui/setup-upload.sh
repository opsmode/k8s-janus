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

# When piped through curl | bash, stdin is occupied by the script which
# breaks interactive terminal reads. Download ourselves fresh and re-exec
# so stdin is free for keyboard input.
_SCRIPT_URL="https://raw.githubusercontent.com/opsmode/k8s-janus/main/webui/setup-upload.sh"
if [[ ! -t 0 ]] && [[ "${_JANUS_REEXEC:-}" != "1" ]]; then
  _TMP=$(mktemp /tmp/janus-setup-XXXXXX)
  curl -fsSL "$_SCRIPT_URL" -o "$_TMP"
  chmod +x "$_TMP"
  _JANUS_REEXEC=1 exec bash "$_TMP" "$@" </dev/tty
fi

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

# _read_key — reads one keypress from /dev/tty into KEY
# Reads escape sequences byte by byte with short timeouts so we never
# accidentally consume script bytes when running via curl | bash.
_read_key() {
  local b1="" b2="" b3=""
  IFS= read -r -s -n1 b1 </dev/tty
  if [[ $b1 == $'\x1b' ]]; then
    IFS= read -r -s -n1 -t 0.05 b2 </dev/tty || true
    if [[ $b2 == "[" ]]; then
      IFS= read -r -s -n1 -t 0.05 b3 </dev/tty || true
    fi
    KEY="${b1}${b2}${b3}"
  else
    KEY="$b1"
  fi
}

# pick_one TITLE item1 item2 ...  — arrow keys to move, Enter to confirm
# Sets global PICK_RESULT to the chosen item
pick_one() {
  local title="$1"; shift
  local items=("$@")
  local cur=0

  _draw_pick_one() {
    printf '\033[%dA' "${#items[@]}" >/dev/tty
    for i in "${!items[@]}"; do
      if [[ $i -eq $cur ]]; then
        printf "  ${GREEN}${BOLD}▶ %s${RESET}\n" "${items[$i]}" >/dev/tty
      else
        printf "    ${DIM}%s${RESET}\n" "${items[$i]}" >/dev/tty
      fi
    done
  }

  printf '\n  %s\n' "$title" >/dev/tty
  for item in "${items[@]}"; do
    printf "    ${DIM}%s${RESET}\n" "$item" >/dev/tty
  done
  _draw_pick_one

  while true; do
    _read_key
    case "$KEY" in
      $'\x1b[A') (( cur > 0 ))              && (( cur-- )); _draw_pick_one ;;
      $'\x1b[B') (( cur < ${#items[@]}-1 )) && (( cur++ )); _draw_pick_one ;;
      $'\n'|$'\r') break ;;
    esac
  done
  PICK_RESULT="${items[$cur]}"
  printf '\n' >/dev/tty
}

# pick_many TITLE item1 item2 ...  — arrow keys, Space to toggle, Enter to confirm
# Sets global PICK_RESULTS array
pick_many() {
  local title="$1"; shift
  local items=("$@")
  local cur=0
  local -a selected=()
  for (( i=0; i<${#items[@]}; i++ )); do selected[$i]=0; done

  _draw_pick_many() {
    printf '\033[%dA' $(( ${#items[@]} + 1 )) >/dev/tty
    for i in "${!items[@]}"; do
      local check="  " color="$DIM"
      [[ ${selected[$i]} -eq 1 ]] && check="${GREEN}✔${RESET}" && color=""
      if [[ $i -eq $cur ]]; then
        printf "  ${BOLD}▶${RESET} [%b] %b%s${RESET}\n" "$check" "$color" "${items[$i]}" >/dev/tty
      else
        printf "    [%b] %b%s${RESET}\n" "$check" "$color" "${items[$i]}" >/dev/tty
      fi
    done
    printf "  ${DIM}↑↓ move  Space=toggle  Enter=confirm${RESET}\n" >/dev/tty
  }

  printf '\n  %s\n' "$title" >/dev/tty
  for item in "${items[@]}"; do
    printf "    [ ] ${DIM}%s${RESET}\n" "$item" >/dev/tty
  done
  printf "  ${DIM}↑↓ move  Space=toggle  Enter=confirm${RESET}\n" >/dev/tty
  _draw_pick_many

  while true; do
    _read_key
    case "$KEY" in
      $'\x1b[A') (( cur > 0 ))              && (( cur-- )); _draw_pick_many ;;
      $'\x1b[B') (( cur < ${#items[@]}-1 )) && (( cur++ )); _draw_pick_many ;;
      ' ')       selected[$cur]=$(( 1 - selected[$cur] )); _draw_pick_many ;;
      $'\n'|$'\r') break ;;
    esac
  done

  PICK_RESULTS=()
  for i in "${!items[@]}"; do
    [[ ${selected[$i]} -eq 1 ]] && PICK_RESULTS+=("${items[$i]}")
  done
  printf '\n' >/dev/tty
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

if [[ -z "$MGMT_CONTEXT" ]]; then
  if [[ ${#ALL_CONTEXTS_PRE[@]} -eq 1 ]]; then
    MGMT_CONTEXT="${ALL_CONTEXTS_PRE[0]}"
    ok "Only one context — using as central: ${MGMT_CONTEXT}"
  else
    # Pre-select current context by moving it to top of list for pick_one
    SORTED_CTXS=()
    [[ -n "$CURRENT_CTX_PRE" ]] && SORTED_CTXS+=("$CURRENT_CTX_PRE")
    for ctx in "${ALL_CONTEXTS_PRE[@]}"; do
      [[ "$ctx" != "$CURRENT_CTX_PRE" ]] && SORTED_CTXS+=("$ctx")
    done
    pick_one "Central cluster (controller + web UI run here) — ↑↓ move, Enter confirm:" "${SORTED_CTXS[@]}"
    MGMT_CONTEXT="$PICK_RESULT"
  fi
fi

ok "Central cluster: ${BOLD}${MGMT_CONTEXT}${RESET}"

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
TMP_DIR=$(mktemp -d)
if $PF_STARTED; then
  trap 'stop_port_forward; rm -rf "$TMP_DIR"' EXIT
else
  trap 'rm -rf "$TMP_DIR"' EXIT
fi

ALL_CONTEXTS=("${ALL_CONTEXTS_PRE[@]}")

if [[ ${#ALL_CONTEXTS[@]} -eq 1 ]]; then
  SELECTED_CONTEXTS=("${ALL_CONTEXTS[@]}")
  ok "Only one context — using: ${SELECTED_CONTEXTS[0]}"
else
  # Build list with central marked; pre-select all by default in pick_many
  PICK_LABELS=()
  for ctx in "${ALL_CONTEXTS[@]}"; do
    if [[ "$ctx" == "$MGMT_CONTEXT" ]]; then
      PICK_LABELS+=("${ctx}  (central)")
    else
      PICK_LABELS+=("$ctx")
    fi
  done

  pick_many "Select contexts to register — ↑↓ move, Space toggle, Enter confirm:" "${PICK_LABELS[@]}"

  SELECTED_CONTEXTS=()
  for label in "${PICK_RESULTS[@]}"; do
    # Strip the " (central)" suffix if present
    ctx="${label%  (central)}"
    SELECTED_CONTEXTS+=("$ctx")
  done

  # Always ensure central is included
  MGMT_ALREADY=false
  for ctx in "${SELECTED_CONTEXTS[@]}"; do
    [[ "$ctx" == "$MGMT_CONTEXT" ]] && MGMT_ALREADY=true && break
  done
  if ! $MGMT_ALREADY; then
    SELECTED_CONTEXTS=("$MGMT_CONTEXT" "${SELECTED_CONTEXTS[@]}")
    warn "Central context added automatically: ${MGMT_CONTEXT}"
  fi

  [[ ${#SELECTED_CONTEXTS[@]} -eq 0 ]] && die "No contexts selected"
  ok "Registering ${#SELECTED_CONTEXTS[@]} context(s)"
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
CONTEXTS_JSON=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('contexts',[])))" 2>/dev/null || echo "[]")

# ==============================================================================
# CLI or browser?
# ==============================================================================
pick_one "How would you like to continue? — ↑↓ move, Enter confirm:" \
  "CLI  — run setup now in this terminal (no browser needed)" \
  "Browser  — open the web wizard to select clusters and watch progress"

SETUP_URL="${WIZARD_URL}/setup${SESSION_ID:+?session=${SESSION_ID}}"
[[ "$PICK_RESULT" == Browser* ]] && MODE_CHOICE="2" || MODE_CHOICE="1"

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
  # Parse context names from upload response
  mapfile -t CTX_NAMES < <(echo "$CONTEXTS_JSON" | python3 -c "
import sys, json
for c in json.load(sys.stdin):
    print(c['name'])
")

  if [[ ${#CTX_NAMES[@]} -eq 0 ]]; then
    die "No contexts available from uploaded kubeconfig"
  fi

  # Central context — pre-sort so MGMT_CONTEXT is at top
  SORTED_CTX_NAMES=("$MGMT_CONTEXT")
  for ctx in "${CTX_NAMES[@]}"; do
    [[ "$ctx" != "$MGMT_CONTEXT" ]] && SORTED_CTX_NAMES+=("$ctx")
  done
  pick_one "Central cluster (controller runs here) — ↑↓ move, Enter confirm:" "${SORTED_CTX_NAMES[@]}"
  CENTRAL_CTX="$PICK_RESULT"
  ok "Central: ${CENTRAL_CTX}"

  # Remote contexts — exclude the central from the list
  REMOTE_CANDIDATES=()
  for ctx in "${CTX_NAMES[@]}"; do
    [[ "$ctx" != "$CENTRAL_CTX" ]] && REMOTE_CANDIDATES+=("$ctx")
  done

  REMOTE_CTXS=()
  if [[ ${#REMOTE_CANDIDATES[@]} -gt 0 ]]; then
    pick_many "Remote clusters — ↑↓ move, Space toggle, Enter confirm (skip all = central only):" "${REMOTE_CANDIDATES[@]}"
    REMOTE_CTXS=("${PICK_RESULTS[@]}")
  fi

  # Build JSON payload
  CENTRAL_JSON=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$CENTRAL_CTX")
  REMOTE_JSON="["
  for ctx in "${REMOTE_CTXS[@]}"; do
    REMOTE_JSON+=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$ctx")","
  done
  REMOTE_JSON="${REMOTE_JSON%,}]"

  RUN_PAYLOAD="{\"session_id\":\"${SESSION_ID}\",\"central_context\":${CENTRAL_JSON},\"remote_contexts\":${REMOTE_JSON}}"

  # Trigger setup
  step "Running setup"
  RUN_RESP=$(curl -sf -X POST "${WIZARD_URL}/setup/run" \
    -H "Content-Type: application/json" \
    -d "$RUN_PAYLOAD" 2>&1) || die "Failed to start setup: $RUN_RESP"

  RUN_ERR=$(echo "$RUN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error') or '')" 2>/dev/null || echo "")
  [[ -n "$RUN_ERR" ]] && die "Setup failed to start: $RUN_ERR"

  # Stream progress via WebSocket (requires python3 websockets or fallback to polling)
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
        base = base.replace(f"/ws/setup/", "/setup/status/")
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
