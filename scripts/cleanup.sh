#!/usr/bin/env bash
# Removes all K8s-Janus resources from one or more clusters.
# Safe to run multiple times — skips resources that don't exist.
#
# Usage:
#   ./scripts/cleanup.sh                          # cleans current context
#   ./scripts/cleanup.sh ctx1 ctx2 ctx3           # cleans specific contexts
#   ./scripts/cleanup.sh --all                    # cleans all contexts in kubeconfig
set -euo pipefail

NAMESPACE="k8s-janus"
CRD_GROUP="opsmode.io"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}  ✔ $*${NC}"; }
warn()    { echo -e "${YELLOW}  ⚠ $*${NC}"; }
section() { echo -e "\n${YELLOW}=== $* ===${NC}"; }

cleanup_context() {
  local ctx=$1
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Cluster: $ctx"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  section "Namespaces"
  NS_LIST=$(kubectl --context "$ctx" get namespaces --no-headers 2>/dev/null \
    | awk '{print $1}' \
    | grep -E "^${NAMESPACE}$|^test-" || true)
  if [ -n "$NS_LIST" ]; then
    for ns in $NS_LIST; do
      kubectl --context "$ctx" delete namespace "$ns" --wait=false 2>/dev/null \
        && info "Deleted namespace: $ns" \
        || warn "Could not delete namespace: $ns"
    done
  else
    info "No janus namespaces found"
  fi

  section "CRDs"
  CRD_LIST=$(kubectl --context "$ctx" get crds -o name 2>/dev/null \
    | grep -E "${CRD_GROUP}|janus" || true)
  if [ -n "$CRD_LIST" ]; then
    for crd in $CRD_LIST; do
      kubectl --context "$ctx" delete "$crd" 2>/dev/null \
        && info "Deleted $crd" \
        || warn "Could not delete $crd"
    done
  else
    info "No janus CRDs found"
  fi

  section "ClusterRoles"
  CR_LIST=$(kubectl --context "$ctx" get clusterroles --no-headers 2>/dev/null \
    | awk '{print $1}' | grep "janus" || true)
  if [ -n "$CR_LIST" ]; then
    for cr in $CR_LIST; do
      kubectl --context "$ctx" delete clusterrole "$cr" 2>/dev/null \
        && info "Deleted ClusterRole: $cr" \
        || warn "Could not delete ClusterRole: $cr"
    done
  else
    info "No janus ClusterRoles found"
  fi

  section "ClusterRoleBindings"
  CRB_LIST=$(kubectl --context "$ctx" get clusterrolebindings --no-headers 2>/dev/null \
    | awk '{print $1}' | grep "janus" || true)
  if [ -n "$CRB_LIST" ]; then
    for crb in $CRB_LIST; do
      kubectl --context "$ctx" delete clusterrolebinding "$crb" 2>/dev/null \
        && info "Deleted ClusterRoleBinding: $crb" \
        || warn "Could not delete ClusterRoleBinding: $crb"
    done
  else
    info "No janus ClusterRoleBindings found"
  fi

  echo ""
  info "Cluster $ctx is clean."
}

# Resolve target contexts
if [ "${1:-}" = "--all" ]; then
  CONTEXTS=$(kubectl config get-contexts --no-headers -o name)
elif [ $# -gt 0 ]; then
  CONTEXTS="$*"
else
  CONTEXTS=$(kubectl config current-context)
fi

echo "K8s-Janus Cleanup Script"
echo "Targets: $CONTEXTS"

for ctx in $CONTEXTS; do
  if ! kubectl config get-contexts "$ctx" &>/dev/null; then
    warn "Context not found, skipping: $ctx"
    continue
  fi
  cleanup_context "$ctx"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done. All targeted clusters cleaned."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
