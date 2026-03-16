#!/usr/bin/env bash
#
# Setup script for remote Janus clusters.
# Run this on each remote cluster to generate a kubeconfig Secret for the central cluster.
#
# Usage:
#   ./setup-remote-cluster.sh <central-cluster-name> [options]
#
# Options:
#   --namespace <ns>          Namespace where Janus is deployed (default: k8s-janus)
#   --service-account <name>  Service account name (default: janus-remote)
#   --token-duration <duration> Token lifetime (default: 8760h = 1 year)
#   --output <file>           Output kubeconfig YAML to file instead of stdout
#   --apply-to-central        Also apply the secret to the central cluster via kubectl
#

set -euo pipefail

# Defaults
NAMESPACE="${NAMESPACE:-k8s-janus}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-janus-remote}"
TOKEN_DURATION="${TOKEN_DURATION:-8760h}"
OUTPUT_FILE=""
APPLY_TO_CENTRAL=false

# Parse arguments
if [ $# -lt 1 ]; then
  echo "Usage: $0 <central-cluster-name> [options]"
  echo ""
  echo "Example:"
  echo "  $0 central --output remote-kubeconfig.yaml"
  exit 1
fi

CENTRAL_CLUSTER_NAME="$1"
shift

while [ $# -gt 0 ]; do
  case "$1" in
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    --service-account)
      SERVICE_ACCOUNT="$2"
      shift 2
      ;;
    --token-duration)
      TOKEN_DURATION="$2"
      shift 2
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --apply-to-central)
      APPLY_TO_CENTRAL=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "🔧 Setting up remote Janus cluster..."
echo "   Namespace: $NAMESPACE"
echo "   Service Account: $SERVICE_ACCOUNT"
echo "   Token Duration: $TOKEN_DURATION"
echo ""

# Get current cluster context
CURRENT_CONTEXT=$(kubectl config current-context)
CLUSTER_NAME=$(kubectl config view -o jsonpath="{.contexts[?(@.name == \"$CURRENT_CONTEXT\")].context.cluster}")
SERVER_URL=$(kubectl config view -o jsonpath="{.clusters[?(@.name == \"$CLUSTER_NAME\")].cluster.server}")

echo "📍 Current cluster:"
echo "   Context: $CURRENT_CONTEXT"
echo "   Cluster: $CLUSTER_NAME"
echo "   Server: $SERVER_URL"
echo ""

# Verify ServiceAccount exists
if ! kubectl get sa "$SERVICE_ACCOUNT" -n "$NAMESPACE" >/dev/null 2>&1; then
  echo "❌ ServiceAccount '$SERVICE_ACCOUNT' not found in namespace '$NAMESPACE'"
  echo "   Deploy Janus in remote mode first:"
  echo "   helm install janus ./helm --namespace $NAMESPACE --create-namespace --set remote.enabled=true"
  exit 1
fi

echo "✅ ServiceAccount found"
echo ""

# Create token
echo "🔑 Creating service account token..."
TOKEN=$(kubectl create token "$SERVICE_ACCOUNT" -n "$NAMESPACE" --duration="$TOKEN_DURATION")

if [ -z "$TOKEN" ]; then
  echo "❌ Failed to create token"
  exit 1
fi

echo "✅ Token created (expires in $TOKEN_DURATION)"
echo ""

# Get CA certificate
echo "📜 Extracting cluster CA certificate..."
CA_DATA=$(kubectl config view --raw -o json | jq -r ".clusters[] | select(.name == \"$CLUSTER_NAME\") | .cluster.\"certificate-authority-data\"")

if [ -z "$CA_DATA" ] || [ "$CA_DATA" = "null" ]; then
  echo "⚠️  No embedded CA found, trying to extract from cluster..."
  CA_DATA=$(kubectl get cm kube-root-ca.crt -o jsonpath='{.data.ca\.crt}' | base64 -w0 2>/dev/null || echo "")
fi

if [ -z "$CA_DATA" ] || [ "$CA_DATA" = "null" ]; then
  echo "❌ Could not extract CA certificate"
  exit 1
fi

echo "✅ CA certificate extracted"
echo ""

# Generate kubeconfig Secret YAML
SECRET_NAME="${CLUSTER_NAME}-kubeconfig"
KUBECONFIG_YAML=$(cat <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${SERVER_URL}
      certificate-authority-data: ${CA_DATA}
contexts:
  - name: ${CLUSTER_NAME}
    context:
      cluster: ${CLUSTER_NAME}
      user: ${SERVICE_ACCOUNT}
current-context: ${CLUSTER_NAME}
users:
  - name: ${SERVICE_ACCOUNT}
    user:
      token: ${TOKEN}
EOF
)

SECRET_YAML=$(cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${SECRET_NAME}
  namespace: ${NAMESPACE}
  labels:
    janus.infroware.com/cluster: "${CLUSTER_NAME}"
    janus.infroware.com/cluster-kubeconfig: "true"
  annotations:
    janus.infroware.com/created: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    janus.infroware.com/token-duration: "${TOKEN_DURATION}"
type: Opaque
data:
  kubeconfig: $(echo "$KUBECONFIG_YAML" | base64 -w0)
EOF
)

# Output or apply
if [ -n "$OUTPUT_FILE" ]; then
  echo "$SECRET_YAML" > "$OUTPUT_FILE"
  echo "✅ Secret YAML written to: $OUTPUT_FILE"
  echo ""
  echo "To apply on central cluster '$CENTRAL_CLUSTER_NAME':"
  echo "  kubectl apply -f $OUTPUT_FILE"
elif $APPLY_TO_CENTRAL; then
  echo "🚀 Applying Secret to central cluster '$CENTRAL_CLUSTER_NAME'..."

  # Switch to central cluster context
  if ! kubectl config use-context "$CENTRAL_CLUSTER_NAME" >/dev/null 2>&1; then
    echo "❌ Cannot switch to central cluster context '$CENTRAL_CLUSTER_NAME'"
    echo "   Available contexts:"
    kubectl config get-contexts -o name | sed 's/^/     /'
    exit 1
  fi

  echo "$SECRET_YAML" | kubectl apply -f -
  echo "✅ Secret applied to central cluster"

  # Switch back to remote cluster
  kubectl config use-context "$CURRENT_CONTEXT" >/dev/null 2>&1
else
  echo "$SECRET_YAML"
fi

echo ""
echo "✅ Remote cluster setup complete!"
echo ""
echo "📝 Next steps:"
echo "   1. Apply the Secret to your central cluster '$CENTRAL_CLUSTER_NAME'"
echo "   2. Restart the Janus controller to discover the new cluster"
echo "   3. Token will expire in $TOKEN_DURATION - set a reminder to refresh"
