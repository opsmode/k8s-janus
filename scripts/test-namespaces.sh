#!/usr/bin/env bash
# Creates 5 test namespaces on each cluster, each with 20 pods (with shell)
# and 2 pods without shell (distroless). Used for manual E2E testing of k8s-janus.
set -euo pipefail

CONTEXTS=(
  "gke_janustest-1_us-central1-a_janustest-1-cluster"
  "gke_janustest-2_us-central1-a_janustest-2-cluster"
  "gke_janustest-3_us-central1-a_janustest-3-cluster"
  "gke_janustest-4_us-central1-a_janustest-4-cluster"
)

# 5 namespaces per cluster (reuse if already exist)
declare -A CLUSTER_NS
CLUSTER_NS["gke_janustest-1_us-central1-a_janustest-1-cluster"]="citadel forge nexus vault ra"
CLUSTER_NS["gke_janustest-2_us-central1-a_janustest-2-cluster"]="hades zeus poseidon forge erebus"
CLUSTER_NS["gke_janustest-3_us-central1-a_janustest-3-cluster"]="mars venus jupiter saturn forge"
CLUSTER_NS["gke_janustest-4_us-central1-a_janustest-4-cluster"]="odin thor freya loki forge"

PHONETIC=("alpha" "bravo" "charlie" "delta" "echo" "foxtrot" "golf" "hotel" "india" "juliet"
          "kilo" "lima" "mike" "november" "oscar" "papa" "quebec" "romeo" "sierra" "tango"
          "uniform" "victor" "whiskey" "xray" "yankee" "zulu")

# Shell pod manifest (ubuntu image — has /bin/bash)
shell_pod() {
  local ns=$1 name=$2
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${ns}
  labels:
    app: test
    k8s-janus.opsmode.io/test: "true"
spec:
  containers:
  - name: app
    image: ubuntu:22.04
    command: ["/bin/bash", "-c"]
    args:
    - |
      msgs=("ERROR: coffee.exe has stopped working"
            "WARNING: keyboard not found, press F1 to continue"
            "INFO: reticulating splines..."
            "DEBUG: have you tried turning it off and on again?"
            "CRITICAL: someone set us up the bomb"
            "INFO: all your base are belong to us"
            "WARNING: dividing by zero... done"
            "ERROR: the matrix has you"
            "INFO: sudo make me a sandwich"
            "WARNING: existential crisis detected in module ego.py"
            "INFO: deploying to production on friday 5pm"
            "ERROR: 418 I am a teapot"
            "CRITICAL: too many cooks"
            "INFO: have you tried git blame?")
      while true; do
        echo "\${msgs[\$((RANDOM % \${#msgs[@]}))]}"
        sleep \$((RANDOM % 4 + 1))
      done
    resources:
      requests: {cpu: 10m, memory: 16Mi}
      limits:   {cpu: 50m, memory: 32Mi}
  restartPolicy: Always
EOF
}

# Distroless pod (no shell)
distroless_pod() {
  local ns=$1 name=$2
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${ns}
  labels:
    app: test-distroless
    k8s-janus.opsmode.io/test: "true"
spec:
  containers:
  - name: app
    image: gcr.io/distroless/static-debian11:latest
    args: ["sleep", "99999"]
    resources:
      requests: {cpu: 5m, memory: 8Mi}
      limits:   {cpu: 20m, memory: 16Mi}
  restartPolicy: Always
EOF
}

for ctx in "${CONTEXTS[@]}"; do
  echo ""
  echo "=== $ctx ==="
  namespaces="${CLUSTER_NS[$ctx]}"

  for ns in $namespaces; do
    echo "  Namespace: $ns"
    kubectl --context "$ctx" get namespace "$ns" &>/dev/null \
      || kubectl --context "$ctx" create namespace "$ns" &>/dev/null \
      && echo "    ✔ namespace ready"

    # Create 20 shell pods
    for i in $(seq 0 19); do
      name="${PHONETIC[$i]}-$((RANDOM % 1000))"
      # Skip if enough pods already running
      existing=$(kubectl --context "$ctx" get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
      if (( existing >= 20 )); then
        echo "    ↩ $ns already has $existing pods, skipping"
        break
      fi
      shell_pod "$ns" "$name" | kubectl --context "$ctx" apply -f - &>/dev/null
    done

    # Create 2 distroless pods (labelled so UI shows "no shell")
    for i in 1 2; do
      name="distroless-${i}-$((RANDOM % 1000))"
      existing=$(kubectl --context "$ctx" get pods -n "$ns" -l app=test-distroless --no-headers 2>/dev/null | wc -l)
      if (( existing >= 2 )); then
        echo "    ↩ distroless pods already exist in $ns"
        break
      fi
      distroless_pod "$ns" "$name" | kubectl --context "$ctx" apply -f - &>/dev/null
    done

    total=$(kubectl --context "$ctx" get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
    echo "    ✔ $total pods in $ns"
  done
done

echo ""
echo "Done. Test pods deployed across all clusters."
