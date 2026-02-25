#!/usr/bin/env bash
# ⛩  K8s-Janus Setup — Interactive cluster onboarding
# Reads your local kubeconfig(s), lets you pick a central cluster and remote
# clusters, then creates the kubeconfig Secrets in the k8s-janus namespace.

set -euo pipefail

# ==============================================================================
# Colors & flair
# ==============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

JANUS_NS="k8s-janus"

banner() {
  echo ""
  echo -e "${MAGENTA}${BOLD}"
  echo "  ⛩   K 8 s - J A N U S   S E T U P"
  echo -e "${RESET}${DIM}  God of Gateways · Just-in-Time Kubernetes Access${RESET}"
  echo ""
}

step()    { echo -e "\n${CYAN}${BOLD}━━━  $*${RESET}"; }
ok()      { echo -e "  ${GREEN}✔${RESET}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}   $*"; }
info()    { echo -e "  ${BLUE}ℹ${RESET}   $*"; }
die()     { echo -e "\n  ${RED}✘  $*${RESET}\n"; exit 1; }
dim()     { echo -e "${DIM}$*${RESET}"; }

# ==============================================================================
# Preflight
# ==============================================================================
banner

step "Checking prerequisites"
if command -v kubectl &>/dev/null; then
  ok "kubectl found"
else
  die "kubectl not found — please install it first"
fi

# ==============================================================================
# Discover available contexts from kubeconfig
# ==============================================================================
step "Reading your kubeconfig contexts"

KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"

if [[ ! -f "$KUBECONFIG_FILE" ]] && [[ -z "${KUBECONFIG:-}" ]]; then
  die "No kubeconfig found at $KUBECONFIG_FILE"
fi

mapfile -t ALL_CONTEXTS < <(kubectl config get-contexts -o name 2>/dev/null)

if [[ ${#ALL_CONTEXTS[@]} -eq 0 ]]; then
  die "No contexts found in your kubeconfig. Add a cluster first."
fi

info "Found ${#ALL_CONTEXTS[@]} context(s):"
echo ""
for i in "${!ALL_CONTEXTS[@]}"; do
  num=$(( i + 1 ))
  current=""
  [[ "${ALL_CONTEXTS[$i]}" == "$(kubectl config current-context 2>/dev/null)" ]] && current=" ${YELLOW}← current${RESET}"
  echo -e "  ${BOLD}[$num]${RESET}  ${ALL_CONTEXTS[$i]}${current}"
done
echo ""

# ==============================================================================
# Pick central cluster
# ==============================================================================
step "Choose your CENTRAL cluster"
echo ""
echo -e "${DIM}  This is where K8s-Janus (controller + web UI) will be deployed.${RESET}"
echo -e "${DIM}  All AccessRequest CRDs and token Secrets will live here.${RESET}"
echo ""

while true; do
  echo -ne "  ${BOLD}Enter number [1-${#ALL_CONTEXTS[@]}]:${RESET} "
  read -r choice
  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#ALL_CONTEXTS[@]} )); then
    CENTRAL_CONTEXT="${ALL_CONTEXTS[$((choice-1))]}"
    break
  fi
  echo -e "  ${RED}Invalid choice — try again${RESET}"
done

ok "Central cluster: ${BOLD}$CENTRAL_CONTEXT${RESET}"

# ==============================================================================
# Pick remote clusters (multi-select)
# ==============================================================================
step "Choose REMOTE clusters to manage"
echo ""
echo -e "${DIM}  These are the clusters where engineers will get temporary pod access.${RESET}"
echo -e "${DIM}  The central cluster is included automatically. Enter numbers separated by spaces.${RESET}"
echo -e "${DIM}  Press Enter to skip (central cluster only).${RESET}"
echo ""

REMOTE_CONTEXTS=()
for i in "${!ALL_CONTEXTS[@]}"; do
  [[ "${ALL_CONTEXTS[$i]}" == "$CENTRAL_CONTEXT" ]] && continue
  num=$(( i + 1 ))
  echo -e "  ${BOLD}[$num]${RESET}  ${ALL_CONTEXTS[$i]}"
done
echo ""

echo -ne "  ${BOLD}Enter numbers (e.g. 2 3 5) or press Enter to skip:${RESET} "
read -r -a remote_choices

for choice in "${remote_choices[@]}"; do
  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#ALL_CONTEXTS[@]} )); then
    ctx="${ALL_CONTEXTS[$((choice-1))]}"
    if [[ "$ctx" != "$CENTRAL_CONTEXT" ]]; then
      REMOTE_CONTEXTS+=("$ctx")
      ok "Remote cluster added: ${BOLD}$ctx${RESET}"
    else
      warn "Skipping central cluster (already included)"
    fi
  else
    warn "Ignoring invalid choice: $choice"
  fi
done

ALL_SELECTED=("$CENTRAL_CONTEXT" "${REMOTE_CONTEXTS[@]}")

echo ""
info "Selected ${#ALL_SELECTED[@]} cluster(s) total"

# ==============================================================================
# Switch to central cluster and ensure namespace exists
# ==============================================================================
step "Connecting to central cluster"

kubectl config use-context "$CENTRAL_CONTEXT" &>/dev/null
ok "Switched to context: $CENTRAL_CONTEXT"

if kubectl get namespace "$JANUS_NS" &>/dev/null 2>&1; then
  ok "Namespace '$JANUS_NS' already exists"
else
  echo -ne "  ${YELLOW}Namespace '$JANUS_NS' not found. Create it?${RESET} [y/N] "
  read -r yn
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    kubectl create namespace "$JANUS_NS"
    kubectl label namespace "$JANUS_NS" \
      app.kubernetes.io/managed-by=Helm --overwrite &>/dev/null
    kubectl annotate namespace "$JANUS_NS" \
      meta.helm.sh/release-name=k8s-janus \
      meta.helm.sh/release-namespace="$JANUS_NS" \
      --overwrite &>/dev/null
    ok "Created namespace '$JANUS_NS'"
  else
    die "Namespace '$JANUS_NS' is required — deploy k8s-janus first or re-run and create it"
  fi
fi

# ==============================================================================
# Export kubeconfigs and create Secrets
# ==============================================================================
step "Creating kubeconfig Secrets in namespace '$JANUS_NS'"

SECRETS_CREATED=()
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

for ctx in "${ALL_SELECTED[@]}"; do
  # Derive a clean secret name from the context
  secret_name="$(echo "$ctx" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/-\+/-/g' | sed 's/^-\|-$//g')-kubeconfig"
  kubeconfig_path="$TMP_DIR/${secret_name}.yaml"

  echo ""
  echo -e "  ${BOLD}$ctx${RESET}"
  echo -e "  ${DIM}→ Secret: $secret_name${RESET}"

  # Build a static kubeconfig using the janus-remote ServiceAccount token.
  # This avoids exec-based auth plugins (e.g. gke-gcloud-auth-plugin) that
  # are not available inside the controller pod.
  cluster_server=$(kubectl config view --minify --flatten --context="$ctx" \
    -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
  cluster_ca=$(kubectl config view --minify --flatten --context="$ctx" \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null)

  # Check janus-remote ServiceAccount exists (requires helm-remote chart deployed)
  if ! kubectl --context="$ctx" get serviceaccount janus-remote \
      -n "$JANUS_NS" &>/dev/null 2>&1; then
    warn "ServiceAccount 'janus-remote' not found on cluster '$ctx'."
    warn "Deploy helm-remote first: helm upgrade --install janus-remote ./helm-remote \\"
    warn "  --kube-context $ctx --namespace $JANUS_NS --create-namespace"
    warn "Then re-run this script."
    continue
  fi

  # Issue a static token for the janus-remote ServiceAccount
  cluster_token=$(kubectl --context="$ctx" create token janus-remote \
    --namespace="$JANUS_NS" --duration=8760h 2>/dev/null)

  if [[ -z "$cluster_server" || -z "$cluster_ca" || -z "$cluster_token" ]]; then
    warn "Could not generate static kubeconfig for context '$ctx' — skipping"
    continue
  fi

  cat > "$kubeconfig_path" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: ${ctx}
  cluster:
    server: ${cluster_server}
    certificate-authority-data: ${cluster_ca}
contexts:
- name: ${ctx}
  context:
    cluster: ${ctx}
    user: janus-remote
current-context: ${ctx}
users:
- name: janus-remote
  user:
    token: ${cluster_token}
EOF

  if kubectl get secret "$secret_name" -n "$JANUS_NS" &>/dev/null 2>&1; then
    kubectl delete secret "$secret_name" -n "$JANUS_NS" &>/dev/null
  fi

  kubectl create secret generic "$secret_name" \
    --from-file=kubeconfig="$kubeconfig_path" \
    --namespace="$JANUS_NS" &>/dev/null
  kubectl label secret "$secret_name" -n "$JANUS_NS" \
    app.kubernetes.io/managed-by=Helm --overwrite &>/dev/null
  kubectl annotate secret "$secret_name" -n "$JANUS_NS" \
    meta.helm.sh/release-name=k8s-janus \
    meta.helm.sh/release-namespace="$JANUS_NS" \
    --overwrite &>/dev/null
  ok "Created secret: ${GREEN}${BOLD}$secret_name${RESET}"
  SECRETS_CREATED+=("$ctx:$secret_name")
done

# ==============================================================================
# Build clusters list
# ==============================================================================
build_clusters_yaml() {
  for entry in "${ALL_SELECTED[@]}"; do
    secret_name="$(echo "$entry" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/-\+/-/g' | sed 's/^-\|-$//g')-kubeconfig"
    display="$(echo "$entry" | awk -F'[/_]' '{print $NF}')"
    echo "    - name: ${entry}"
    echo "      displayName: \"${display}\""
    echo "      secretName: \"${secret_name}\""
  done
}

# ==============================================================================
# Patch values.yaml or print snippet
# ==============================================================================
step "Done! 🎉"
echo ""

if [[ ${#SECRETS_CREATED[@]} -gt 0 ]]; then

  # Detect helm/values.yaml relative to the script location
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  VALUES_FILE="${SCRIPT_DIR}/../helm/values.yaml"

  if [[ -f "$VALUES_FILE" ]] && command -v yq &>/dev/null; then
    echo -ne "  ${YELLOW}Auto-update helm/values.yaml with the cluster list?${RESET} [Y/n] "
    read -r yn
    if [[ ! "$yn" =~ ^[Nn]$ ]]; then
      # Build a yq-compatible clusters array and replace the clusters key
      NEW_CLUSTERS="["
      first=1
      for entry in "${ALL_SELECTED[@]}"; do
        secret_name="$(echo "$entry" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/-\+/-/g' | sed 's/^-\|-$//g')-kubeconfig"
        display="$(echo "$entry" | awk -F'[/_]' '{print $NF}')"
        [[ $first -eq 0 ]] && NEW_CLUSTERS+=","
        NEW_CLUSTERS+="{\"name\":\"${entry}\",\"displayName\":\"${display}\",\"secretName\":\"${secret_name}\"}"
        first=0
      done
      NEW_CLUSTERS+="]"
      yq -i ".clusters = ${NEW_CLUSTERS}" "$VALUES_FILE"
      ok "Updated clusters in ${VALUES_FILE}"
    else
      echo -e "${BOLD}  Add this to your helm/values.yaml:${RESET}"
      echo ""
      echo -e "${GREEN}  clusters:"
      build_clusters_yaml
      echo -e "${RESET}"
    fi
  else
    # yq not available or values.yaml not found — just print
    echo -e "${BOLD}  Add this to your helm/values.yaml:${RESET}"
    echo ""
    echo -e "${GREEN}  clusters:"
    build_clusters_yaml
    echo -e "${RESET}"
    [[ ! -f "$VALUES_FILE" ]] && warn "helm/values.yaml not found at expected path: ${VALUES_FILE}"
    command -v yq &>/dev/null || warn "Install yq to enable auto-update: https://github.com/mikefarah/yq"
  fi

  echo -e "  Redeploy to apply:"
  echo -e "${CYAN}"
  echo "    helm upgrade --install k8s-janus ./helm \\"
  echo "      --namespace $JANUS_NS --reuse-values"
  echo -e "${RESET}"
fi


echo -e "${MAGENTA}${BOLD}  ⛩  The gate is ready. Go govern it.${RESET}"
echo ""
