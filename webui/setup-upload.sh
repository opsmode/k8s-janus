#!/usr/bin/env bash
# ⛩  K8s-Janus Setup — registers remote clusters with the Janus controller
#
# Usage:
#   bash setup-upload.sh [--port 8080] [--namespace k8s-janus] [--kubeconfig ~/.kube/config]
#                        [--management-context <context-name>] [--mode cli|browser]
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
MODE=""   # cli | browser
PF_PID=""
PF_STARTED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)                PORT="$2";            shift 2 ;;
    --namespace)           JANUS_NS="$2";        shift 2 ;;
    --kubeconfig)          KUBECONFIG_FILE="$2"; shift 2 ;;
    --management-context)  MGMT_CONTEXT="$2";    shift 2 ;;
    --mode)                MODE="$2";            shift 2 ;;
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
echo -e "${MAGENTA}${BOLD}  ⛩   K 8 s - J A N U S   S E T U P${RESET}"
echo -e "${DIM}  Register remote clusters with the Janus controller${RESET}"
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
# CLI or Browser?
# ==============================================================================
if [[ -z "$MODE" ]]; then
  step "How would you like to run setup?"
  echo ""
  echo -e "  ${BOLD}1)${RESET} ${GREEN}CLI${RESET}      — run entirely in this terminal, no browser needed"
  echo -e "  ${BOLD}2)${RESET} ${CYAN}Browser${RESET}  — open the web wizard (visual progress, manage clusters)"
  echo ""
  tty_read "  Choice [1]: " MODE_CHOICE
  [[ -z "$MODE_CHOICE" ]] && MODE_CHOICE="1"
  [[ "$MODE_CHOICE" == "2" ]] && MODE="browser" || MODE="cli"
fi

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
# Select which contexts to include
# ==============================================================================
step "Select contexts to register"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

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
# Flatten + resolve exec-based auth (needed for both modes)
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
# Branch: CLI mode
# ==============================================================================
if [[ "$MODE" == "cli" ]]; then

  step "Running setup via CLI"

  # Determine remote contexts (everything except central)
  REMOTE_CONTEXTS=()
  for ctx in "${SELECTED_CONTEXTS[@]}"; do
    [[ "$ctx" != "$MGMT_CONTEXT" ]] && REMOTE_CONTEXTS+=("$ctx")
  done

  python3 - "$RESOLVED" "$MGMT_CONTEXT" "$JANUS_NS" "${REMOTE_CONTEXTS[@]}" <<'CLIEOF'
import sys, os, json, base64, time, re
import yaml

resolved_path  = sys.argv[1]
central_ctx    = sys.argv[2]
janus_ns       = sys.argv[3]
remote_ctxs    = sys.argv[4:]

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; RESET="\033[0m"

def log(tag, msg):
    colors = {"OK": GREEN+BOLD, "ERROR": RED+BOLD, "WARN": YELLOW, "INFO": CYAN, "DONE": GREEN+BOLD}
    c = colors.get(tag, "")
    print(f"  [{tag}]{c} {msg}{RESET}", flush=True)

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except ImportError:
    log("ERROR", "kubernetes Python package not found.")
    log("INFO",  "Install it with:  pip install kubernetes")
    sys.exit(1)

kc = yaml.safe_load(open(resolved_path))

RULES = [
    {"apiGroups": [""],   "resources": ["namespaces"],              "verbs": ["get","list"]},
    {"apiGroups": [""],   "resources": ["serviceaccounts"],         "verbs": ["get","create","delete"]},
    {"apiGroups": [""],   "resources": ["serviceaccounts/token"],   "verbs": ["create"]},
    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"],  "verbs": ["get","create","delete"]},
    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],  "verbs": ["get","create","update","patch","delete","escalate","bind"]},
    {"apiGroups": [""],   "resources": ["pods","pods/log"],         "verbs": ["get","list"]},
    {"apiGroups": [""],   "resources": ["events"],                  "verbs": ["get","list","create","patch","update"]},
]

def slugify(name):
    s = name.lower()
    s = re.sub(r'[^a-z0-9-]', '-', s)
    s = re.sub(r'-+', '-', s).strip('-')
    return s[:63]

def build_clients(ctx):
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False)
    yaml.dump(kc, tmp)
    tmp.close()
    cfg = client.Configuration()
    loader = config.load_kube_config(config_file=tmp.name, context=ctx, client_configuration=cfg)
    os.unlink(tmp.name)
    api = client.ApiClient(configuration=cfg)
    return client.CoreV1Api(api), client.RbacAuthorizationV1Api(api)

def apply_rbac(core, rbac, ns):
    # Namespace
    try: core.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=ns)))
    except ApiException as e:
        if e.status != 409: raise

    # ServiceAccount
    sa = client.V1ServiceAccount(metadata=client.V1ObjectMeta(name="janus-remote", namespace=ns))
    try: core.create_namespaced_service_account(ns, sa)
    except ApiException as e:
        if e.status != 409: raise

    # ClusterRole
    cr = client.V1ClusterRole(
        metadata=client.V1ObjectMeta(name="janus-remote"),
        rules=[client.V1PolicyRule(**r) for r in RULES]
    )
    try: rbac.create_cluster_role(cr)
    except ApiException as e:
        if e.status == 409: rbac.replace_cluster_role("janus-remote", cr)
        else: raise

    # ClusterRoleBinding
    crb = client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name="janus-remote"),
        role_ref=client.V1RoleRef(api_group="rbac.authorization.k8s.io", kind="ClusterRole", name="janus-remote"),
        subjects=[client.V1Subject(kind="ServiceAccount", name="janus-remote", namespace=ns)]
    )
    try: rbac.create_cluster_role_binding(crb)
    except ApiException as e:
        if e.status != 409: raise

def issue_token(core, ns):
    from kubernetes.client.models import V1TokenRequest, V1TokenRequestSpec
    resp = core.create_namespaced_service_account_token(
        "janus-remote", ns,
        body=V1TokenRequest(spec=V1TokenRequestSpec(expiration_seconds=31_536_000))
    )
    return resp.status.token

def get_server_ca(ctx):
    for c in kc.get("contexts", []):
        if c["name"] == ctx:
            cluster_name = c["context"]["cluster"]
            break
    for cl in kc.get("clusters", []):
        if cl["name"] == cluster_name:
            server = cl["cluster"]["server"]
            ca = cl["cluster"].get("certificate-authority-data", "")
            return server, ca
    raise ValueError(f"cluster not found for context {ctx}")

# Central in-cluster client for creating secrets
try:
    config.load_incluster_config()
except config.ConfigException:
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False)
    yaml.dump(kc, tmp)
    tmp.close()
    config.load_kube_config(config_file=tmp.name, context=central_ctx)
    os.unlink(tmp.name)
central_core = client.CoreV1Api()

log("INFO", f"Central cluster: {central_ctx} (no secret needed)")

errors = 0
for i, ctx in enumerate(remote_ctxs, 1):
    slug = slugify(ctx)
    log("INFO", f"[{i}/{len(remote_ctxs)}] {ctx} → {slug}")
    try:
        log("INFO", "  Checking connectivity...")
        core, rbac = build_clients(ctx)
        core.list_namespace(_request_timeout=10)
        log("OK",   "  Cluster reachable")

        log("INFO", "  Applying RBAC...")
        apply_rbac(core, rbac, janus_ns)
        log("OK",   "  RBAC applied")

        log("INFO", "  Issuing token (1 year)...")
        token = issue_token(core, janus_ns)
        log("OK",   "  Token issued")

        server, ca = get_server_ca(ctx)
        kc_dict = {
            "apiVersion": "v1", "kind": "Config",
            "clusters": [{"name": slug, "cluster": {"server": server, "certificate-authority-data": ca}}],
            "users": [{"name": "janus-remote", "user": {"token": token}}],
            "contexts": [{"name": slug, "context": {"cluster": slug, "user": "janus-remote"}}],
            "current-context": slug,
        }
        secret_name = f"{slug}-kubeconfig"
        log("INFO", f"  Creating secret '{secret_name}'...")
        data = {"kubeconfig": base64.b64encode(yaml.dump(kc_dict).encode()).decode()}
        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=secret_name, namespace=janus_ns,
                labels={"k8s-janus.opsmode.io/managed": "true"}
            ),
            data=data
        )
        try: central_core.create_namespaced_secret(janus_ns, secret)
        except ApiException as e:
            if e.status == 409: central_core.replace_namespaced_secret(secret_name, janus_ns, secret)
            else: raise
        log("OK",   f"  Secret '{secret_name}' ready")

    except Exception as e:
        log("ERROR", f"{ctx}: {e}")
        errors += 1

if errors == len(remote_ctxs) and remote_ctxs:
    log("ERROR", "All remote clusters failed.")
    sys.exit(1)

log("DONE", "Setup complete — Janus is ready.")
CLIEOF

  echo ""
  echo -e "${MAGENTA}${BOLD}  ⛩  Done. Janus controller will start once it detects the secrets.${RESET}"
  echo ""
  exit 0
fi

# ==============================================================================
# Branch: Browser mode — port-forward + upload + open browser
# ==============================================================================
step "Checking wizard at ${WIZARD_URL}"

stop_port_forward() {
  if [[ -n "$PF_PID" ]] && kill -0 "$PF_PID" 2>/dev/null; then
    kill "$PF_PID" 2>/dev/null || true
  fi
}
trap 'stop_port_forward; rm -rf "$TMP_DIR"' EXIT

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

step "Uploading to wizard"

RESPONSE=$(curl -sf --max-time 15 -X POST \
  "${WIZARD_URL}/setup/upload" \
  -F "kubeconfig=@${RESOLVED}" \
  -H "Accept: application/json" 2>&1) || {
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${WIZARD_URL}/healthz" 2>/dev/null || echo "000")
  die "Upload request failed (wizard health: HTTP ${HTTP_CODE}).\n\n  Is the port-forward still running and the wizard ready?\n    kubectl --context ${MGMT_CONTEXT} get pods -n ${JANUS_NS}"
}

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

step "Opening wizard in browser"

SETUP_URL="${WIZARD_URL}/setup${SESSION_ID:+?session=${SESSION_ID}}"

echo ""
echo -e "  ${BOLD}Open this URL in your browser:${RESET}"
echo -e "  ${CYAN}${SETUP_URL}${RESET}"
echo ""
if command -v open &>/dev/null; then
  open "$SETUP_URL" 2>/dev/null && ok "Browser opened automatically" || true
elif command -v xdg-open &>/dev/null; then
  xdg-open "$SETUP_URL" 2>/dev/null || true
fi

echo ""
echo -e "${MAGENTA}${BOLD}  ⛩  Kubeconfig uploaded — complete setup in your browser.${RESET}"
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
echo ""
