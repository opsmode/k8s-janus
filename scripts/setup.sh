#!/usr/bin/env bash
# ⛩  K8s-Janus Setup — Interactive cluster onboarding
# Reads your local kubeconfig(s), lets you pick a central cluster and remote
# clusters, deploys helm-remote to each, then creates static kubeconfig Secrets
# in the k8s-janus namespace on the central cluster.

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELM_CHART="${SCRIPT_DIR}/../helm"
HELM_CHART="${SCRIPT_DIR}/../helm"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

step "Checking prerequisites"
for bin in kubectl helm; do
  if command -v "$bin" &>/dev/null; then
    ok "$bin found"
  else
    die "$bin not found — please install it first"
  fi
done

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
# Deploy remote agent to every selected cluster
# ==============================================================================
step "Deploying remote agent to remote clusters"
echo ""
echo -e "${DIM}  Installs the janus-remote ServiceAccount + RBAC on each remote cluster${RESET}"
echo -e "${DIM}  using the main chart with --set remote.enabled=true.${RESET}"
echo ""

if [[ ! -d "$HELM_CHART" ]]; then
  die "Helm chart not found at $HELM_CHART"
fi

for ctx in "${REMOTE_CONTEXTS[@]}"; do
  echo -e "  ${BOLD}$ctx${RESET}"

  # If old janus-remote release exists, uninstall it first
  if helm status janus-remote --kube-context "$ctx" --namespace "$JANUS_NS" \
      &>/dev/null 2>&1; then
    warn "Old janus-remote release found on '$ctx' — removing it"
    helm uninstall janus-remote --kube-context "$ctx" --namespace "$JANUS_NS" \
      &>/dev/null
    ok "Removed old janus-remote release from ${BOLD}$ctx${RESET}"
  fi

  if helm upgrade --install k8s-janus "$HELM_CHART" \
      --kube-context "$ctx" \
      --namespace "$JANUS_NS" \
      --create-namespace \
      --set remote.enabled=true \
      --wait \
      --timeout 60s \
      &>/dev/null; then
    # Verify the SA actually exists after deploy
    if kubectl --context="$ctx" get serviceaccount janus-remote \
        -n "$JANUS_NS" &>/dev/null 2>&1; then
      ok "Remote agent deployed on ${BOLD}$ctx${RESET}"
    else
      warn "Deploy reported success but SA missing on '$ctx'"
      warn "Try: helm uninstall k8s-janus --kube-context $ctx -n $JANUS_NS && re-run setup.sh"
    fi
  else
    warn "Remote agent deploy failed on '$ctx' — skipping this cluster"
  fi
done

# ==============================================================================
# Switch to central cluster and ensure namespace exists
# ==============================================================================
step "Connecting to central cluster"

kubectl config use-context "$CENTRAL_CONTEXT" &>/dev/null
ok "Switched to context: $CENTRAL_CONTEXT"

if kubectl get namespace "$JANUS_NS" &>/dev/null 2>&1; then
  ok "Namespace '$JANUS_NS' already exists"
else
  kubectl create namespace "$JANUS_NS" &>/dev/null
  kubectl label namespace "$JANUS_NS" \
    app.kubernetes.io/managed-by=Helm --overwrite &>/dev/null
  kubectl annotate namespace "$JANUS_NS" \
    meta.helm.sh/release-name=k8s-janus \
    meta.helm.sh/release-namespace="$JANUS_NS" \
    --overwrite &>/dev/null
  ok "Created namespace '$JANUS_NS'"
fi

# ==============================================================================
# Build cluster list for values.yaml (before installing main chart)
# ==============================================================================
build_clusters_json() {
  local result="["
  local first=1
  for entry in "${ALL_SELECTED[@]}"; do
    local display
    display="$(echo "$entry" | awk -F'[/_]' '{print $NF}')"
    [[ $first -eq 0 ]] && result+=","
    result+="{\"name\":\"${entry}\",\"displayName\":\"${display}\"}"
    first=0
  done
  result+="]"
  echo "$result"
}

build_clusters_yaml() {
  for entry in "${ALL_SELECTED[@]}"; do
    local display
    display="$(echo "$entry" | awk -F'[/_]' '{print $NF}')"
    echo "    - name: ${entry}"
    echo "      displayName: \"${display}\""
  done
}

# ==============================================================================
# Deploy main Janus chart to central cluster
# ==============================================================================
step "Deploying K8s-Janus to central cluster"
echo ""
echo -e "${DIM}  Installing (or upgrading) the k8s-janus Helm release.${RESET}"
echo ""

VALUES_FILE="${SCRIPT_DIR}/../helm/values.yaml"

if [[ -d "$HELM_CHART" ]]; then
  # Apply the CRD first (Helm does not upgrade CRDs automatically)
  if [[ -f "${HELM_CHART}/crds/accessrequest.yaml" ]]; then
    kubectl apply -f "${HELM_CHART}/crds/accessrequest.yaml" &>/dev/null
    ok "CRD applied"
  fi

  # Write clusters to a temp values file — avoids quoting issues with --set JSON
  CLUSTERS_VALUES="$TMP_DIR/clusters-override.yaml"
  {
    echo "clusters:"
    for entry in "${ALL_SELECTED[@]}"; do
      local_display="$(echo "$entry" | awk -F'[/_]' '{print $NF}')"
      echo "  - name: ${entry}"
      echo "    displayName: \"${local_display}\""
    done
  } > "$CLUSTERS_VALUES"

  if helm upgrade --install k8s-janus "$HELM_CHART" \
      --kube-context "$CENTRAL_CONTEXT" \
      --namespace "$JANUS_NS" \
      --create-namespace \
      --values "$CLUSTERS_VALUES" \
      --reuse-values \
      --wait \
      --timeout 120s \
      &>/dev/null; then
    ok "k8s-janus deployed on central cluster ${BOLD}$CENTRAL_CONTEXT${RESET}"
  else
    warn "Helm deploy failed — check 'helm status k8s-janus -n $JANUS_NS' for details"
    warn "Continuing with kubeconfig Secret creation..."
  fi
else
  warn "helm/ chart not found at $HELM_CHART — skipping main chart deploy"
fi

# ==============================================================================
# Extract static tokens and create kubeconfig Secrets
# ==============================================================================
step "Creating kubeconfig Secrets in namespace '$JANUS_NS'"

SECRETS_CREATED=()

for ctx in "${ALL_SELECTED[@]}"; do
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

  # Issue a static token for the janus-remote ServiceAccount.
  # grep for the JWT (starts with 'ey') to strip any GKE expiry warnings
  # that kubectl prints to stdout when the cluster caps token duration.
  token_err=$(mktemp)
  cluster_token=$(kubectl --context="$ctx" create token janus-remote \
    --namespace="$JANUS_NS" --duration=8760h 2>"$token_err" \
    | grep '^ey' || true)
  if [[ -z "$cluster_token" ]]; then
    warn "Could not issue token for 'janus-remote' on '$ctx':"
    warn "  $(cat "$token_err")"
    rm -f "$token_err"
    continue
  fi
  rm -f "$token_err"

  if [[ -z "$cluster_server" || -z "$cluster_ca" ]]; then
    warn "Could not read cluster endpoint/CA for context '$ctx' — skipping"
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

  # Always recreate the Secret (override stale tokens)
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
# Patch values.yaml with cluster list
# ==============================================================================
step "Updating cluster list"
echo ""

VALUES_FILE="${SCRIPT_DIR}/../helm/values.yaml"

if [[ ${#SECRETS_CREATED[@]} -gt 0 ]]; then
  if [[ -f "$VALUES_FILE" ]] && command -v yq &>/dev/null; then
    yq -i ".clusters = $(build_clusters_json)" "$VALUES_FILE"
    ok "Updated clusters in ${VALUES_FILE}"
  else
    echo -e "${BOLD}  Add this to your helm/values.yaml:${RESET}"
    echo ""
    echo -e "${GREEN}  clusters:"
    build_clusters_yaml
    echo -e "${RESET}"
    [[ ! -f "$VALUES_FILE" ]] && warn "helm/values.yaml not found at: ${VALUES_FILE}"
    command -v yq &>/dev/null || warn "Install yq to enable auto-update: https://github.com/mikefarah/yq"
  fi

  echo ""
  echo -e "  Re-run this script any time to refresh tokens or add clusters."
  echo -e "  To upgrade manually (e.g. after editing values.yaml):"
  echo -e "${CYAN}"
  echo "    helm upgrade k8s-janus ./helm --namespace $JANUS_NS --reuse-values"
  echo -e "${RESET}"
fi

echo -e "${MAGENTA}${BOLD}  ⛩  The gate is ready. Go govern it.${RESET}"
echo ""
