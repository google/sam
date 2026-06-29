#!/usr/bin/env bash
# Kind dev mesh: a hub plus the nodes declared in mesh-config.yaml, each pinned
# to its own k8s node, with live per-pod logs in named tmux panes.
set -euo pipefail

CLUSTER="sam-kind"
NAMESPACE="sam-kind"
SESSION="sam-kind"
KCTX="kind-${CLUSTER}"
IMAGE_TAG="local"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

check_prereqs() {
  local bins=(kind kubectl docker jq envsubst awk)
  [[ "${1:-}" != "-s" ]] && bins+=(tmux)
  for bin in "${bins[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || { echo "missing prerequisite: $bin" >&2; exit 1; }
  done
  if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    echo "kind cluster '${CLUSTER}' already exists; delete it first: make kind-down" >&2
    exit 1
  fi
}


render_and_apply() {
  local node="$1" svc="$2"
  local CONFIG_ARG="" CONFIG_MOUNT="" SIDECAR="" CONFIG_VOLUME=""
  if [[ -n "$svc" ]]; then
    local dir="${PROJECT_ROOT}/development/examples/${svc}"
    [[ -d "$dir" ]] || { echo "service '${svc}' (node ${node}) not found in development/examples/" >&2; exit 1; }
    echo "Building service image ${svc}:${IMAGE_TAG}…"
    docker build -t "${svc}:${IMAGE_TAG}" "$dir"
    kind load docker-image --name "${CLUSTER}" "${svc}:${IMAGE_TAG}"
    kubectl --context "${KCTX}" -n "${NAMESPACE}" create configmap "${node}-config" \
      --from-file=sam-node.yaml="${dir}/sam-node-config.yaml" \
      --dry-run=client -o yaml | kubectl --context "${KCTX}" apply -f -
    CONFIG_ARG='        - "--config=/etc/sam/sam-node.yaml"'
    CONFIG_MOUNT=$'        - name: config\n          mountPath: /etc/sam'
    SIDECAR=$'      - name: '"${svc}"$'\n        image: '"${svc}:${IMAGE_TAG}"$'\n        imagePullPolicy: IfNotPresent'
    CONFIG_VOLUME=$'      - name: config\n        configMap:\n          name: '"${node}-config"
  fi
  NODE="$node" CONFIG_ARG="$CONFIG_ARG" CONFIG_MOUNT="$CONFIG_MOUNT" SIDECAR="$SIDECAR" CONFIG_VOLUME="$CONFIG_VOLUME" \
    envsubst '${NODE} ${NAMESPACE} ${IMAGE_TAG} ${CONFIG_ARG} ${CONFIG_MOUNT} ${SIDECAR} ${CONFIG_VOLUME}' \
    < "${SCRIPT_DIR}/node.template.yaml" | kubectl --context "${KCTX}" apply -f -
}

# logs: $1 = pane name (printed in-pane and set as the pane title); $2 = logs target.
logs() { echo "printf '\\033[1;36m==== %s ====\\033[0m\\n' '$1'; kubectl --context ${KCTX} -n ${NAMESPACE} logs -f $2; echo; echo '[$1 pane exited; press enter]'; read"; }

# tmuxs: tmux wrapper to ensure that bypass any tmux config the user might be using
tmuxs() { tmux -L samsocket -f /dev/null "$@"; }

show_cluster_logs() {
    tmuxs kill-session -t "${SESSION}" 2>/dev/null || true

  tmuxs new-session -d -s "${SESSION}" -n mesh "$(logs hub 'deploy/sam-hub')" \; set -t "${SESSION}" destroy-unattached off
  for node in "${NODES[@]}"; do
    tmuxs split-window -t "${SESSION}:0" "$(logs "$node" "deploy/${node} -c sam-node")"
    tmuxs select-layout -t "${SESSION}:0" tiled
  done
  tmuxs set-option -t "${SESSION}" -g pane-border-status top
  tmuxs set-option -t "${SESSION}" -g pane-border-format ' #{pane_title} '

  # Title the tmux panes in creation order: hub first, then the nodes.
  titles=(hub "${NODES[@]}")
  i=0
  for pane in $(tmuxs list-panes -t "${SESSION}:0" -F '#{pane_id}'); do
    tmuxs select-pane -t "$pane" -T "${titles[$i]}"
    i=$((i+1))
  done

  read -r -p "Press enter to show cluster logs…" _
  tmuxs attach-session -t "${SESSION}"
}

# Read the node -> service assignment from mesh-config.yaml into NODE_LINES
# (each line: "<node> <service-or-empty>") and the NODES array.
read_mesh_nodes() {
  mapfile -t NODE_LINES < <(awk -F: '/^[A-Za-z0-9_-]+:/{n=$1; s=$2; gsub(/[[:space:]]/,"",n); gsub(/[[:space:]]/,"",s); print n, s}' "${SCRIPT_DIR}/mesh-config.yaml")
  NODES=()
  for line in "${NODE_LINES[@]}"; do NODES+=("${line%% *}"); done
}


### MAIN ###


if [[ $# -gt 0 && "$1" != "-s" && "$1" != "-l" ]]; then
  echo "usage: $(basename "$0") [-s]" >&2
  exit 1
fi

if [[ "${1:-}" == "-l" ]]; then
  read_mesh_nodes
  show_cluster_logs
  exit 0
fi

check_prereqs "${1:-}"

echo "== Creating kind cluster '${CLUSTER}' =="
kind create cluster --name "${CLUSTER}" --config "${SCRIPT_DIR}/kind-config.yaml"

echo "== Building sam images =="
make docker-build-hub docker-build-node
echo "== Loading sam images into kind =="
kind load docker-image --name "${CLUSTER}" "sam-hub:${IMAGE_TAG}" "sam-node:${IMAGE_TAG}"

read_mesh_nodes

# Apply the hub and wait until it accepts connections
ISSUER="$(kubectl --context "${KCTX}" get --raw /.well-known/openid-configuration | jq -r .issuer)"
[[ -n "$ISSUER" ]] || { echo "could not determine cluster OIDC issuer" >&2; exit 1; }
export NAMESPACE ISSUER IMAGE_TAG

echo "== Applying sam-hub (issuer: ${ISSUER}) =="
for f in "${SCRIPT_DIR}"/00-*.yaml "${SCRIPT_DIR}"/10-*.yaml; do
  envsubst '${NAMESPACE} ${ISSUER} ${IMAGE_TAG}' < "$f" | kubectl --context "${KCTX}" apply -f -
done

echo "== Waiting for sam-hub to be ready =="
kubectl --context "${KCTX}" -n "${NAMESPACE}" wait --for=condition=available --timeout=180s deployment/sam-hub

echo "== Applying sam-nodes =="
for line in "${NODE_LINES[@]}"; do
  node="${line%% *}"; svc="${line#* }"; [[ "$svc" == "$node" ]] && svc=""
  render_and_apply "$node" "$svc"
done

echo "== Waiting for sam-nodes =="
for node in "${NODES[@]}"; do
  kubectl --context "${KCTX}" -n "${NAMESPACE}" wait --for=condition=available --timeout=180s "deployment/${node}"
done

echo
echo "Mesh up. To call a node's MCP API, port-forward it in another shell, e.g.:"
echo "  kubectl --context ${KCTX} -n ${NAMESPACE} port-forward deploy/node-a 9091:8080"
echo "then:"
echo "  ./bin/mcp-client -url http://127.0.0.1:9091/mcp -tool find_remote_tools -args '{}'"

if [[ "${1:-}" != "-s" ]]; then
  show_cluster_logs
fi
