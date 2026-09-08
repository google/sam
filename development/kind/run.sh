#!/usr/bin/env bash
# Kind dev mesh: control plane, router, console and Dex, with live per-pod logs in named tmux
# panes. No sam-nodes are deployed — put services on the mesh with charts/sam-node (see the
# epilogue below) or enroll a local node. Gateway addresses come from cloud-provider-kind.
set -euo pipefail

CLUSTER="sam-kind"
NAMESPACE="sam-kind"
SESSION="sam-kind"
KCTX="kind-${CLUSTER}"
IMAGE_TAG="local"
CONTROL_PLANE_URL="http://sam-mesh-control-plane:8080"
HELM="helm"
# Serves the gateway LoadBalancer IPs. It installs the Gateway API CRDs and the
# cloud-provider-kind GatewayClass itself, so the cluster needs no CRD step.
CPK_CONTAINER="cloud-provider-kind"
CPK_IMAGE="registry.k8s.io/cloud-provider-kind/cloud-controller-manager:v0.11.1"
CONSOLE_BASE_PATH="/console"



SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

check_prereqs() {
  local bins=(kind kubectl docker jq envsubst)
  [[ "${1:-}" != "-s" ]] && bins+=(tmux)
  for bin in "${bins[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || { echo "missing prerequisite: $bin" >&2; exit 1; }
  done

  if ! command -v helm >/dev/null 2>&1; then
    if [[ -x "${PROJECT_ROOT}/bin/helm" ]]; then
      HELM="${PROJECT_ROOT}/bin/helm"
    else
      echo "missing prerequisite: helm (install helm or run: curl -fsSL https://get.helm.sh/helm-v3.12.0-linux-amd64.tar.gz | tar -xz -C bin/ --strip-components=1 linux-amd64/helm)" >&2
      exit 1
    fi
  fi

  if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    echo "kind cluster '${CLUSTER}' already exists; delete it first: make kind-down" >&2
    exit 1
  fi
}

# cloud-provider-kind names each gateway's envoy container after a hash of the gateway, so
# one left behind by a deleted cluster is adopted by the next run and reported Programmed
# while its config stream is dead and it serves nothing.
remove_lb_containers() {
  local containers
  containers="$(docker ps -aq -f "label=io.x-k8s.cloud-provider-kind.cluster=${CLUSTER}")"
  if [[ -n "${containers}" ]]; then
    # shellcheck disable=SC2086 # one container id per argument
    docker rm -f ${containers} >/dev/null
  fi
}

# Must run after the cluster, so the 'kind' docker network exists.
start_cloud_provider_kind() {
  remove_lb_containers
  if [[ -n "$(docker ps -q -f "name=^${CPK_CONTAINER}$")" ]]; then
    echo "cloud-provider-kind already running"
    return
  fi
  docker rm -f "${CPK_CONTAINER}" >/dev/null 2>&1 || true
  docker run -d --name "${CPK_CONTAINER}" --network kind \
    -v /var/run/docker.sock:/var/run/docker.sock "${CPK_IMAGE}" >/dev/null
}

# Stop cloud-provider-kind before its containers, or it recreates them, and remove them before
# deleting the cluster, or deleting it makes cloud-provider-kind race us to the same containers.
teardown() {
  docker rm -f "${CPK_CONTAINER}" >/dev/null 2>&1 || true
  remove_lb_containers
  kind delete cluster --name "${CLUSTER}"
}

# gateway_ip <gateway>: the LoadBalancer address cloud-provider-kind assigned, waited for.
gateway_ip() {
  local gateway="$1" ip=""
  for _ in $(seq 1 60); do
    ip="$(kubectl --context "${KCTX}" -n "${NAMESPACE}" get gateway "${gateway}" \
      -o jsonpath='{.status.addresses[0].value}' 2>/dev/null || true)"
    [[ -n "$ip" ]] && { echo "$ip"; return 0; }
    sleep 2
  done
  echo "gateway '${gateway}' never got a LoadBalancer address; is cloud-provider-kind running?" >&2
  return 1
}

# deploy_chart [extra --set flags]: later flags win, so phase 2 overrides phase 1.
# TLS verification is skipped because one issuer is the kind cluster's own API server,
# served with a self-signed cert.
# bootstrap.nodeServices is fail closed by default; this is a local dev mesh whose
# nodes host whatever example service is being tested, so grant them everything
# explicitly here rather than weakening the chart default.
deploy_chart() {
  "${HELM}" --kube-context "${KCTX}" upgrade --install sam-mesh "${PROJECT_ROOT}/charts/sam-mesh" --timeout 10m \
    --namespace "${NAMESPACE}" \
    --set global.imageTag="${IMAGE_TAG}" \
    --set controlPlane.oidcIssuer="${CONTROL_PLANE_ISSUERS//,/\\,}" \
    --set controlPlane.allowedAudiences="${ALLOWED_AUDIENCES//,/\\,}" \
    --set controlPlane.insecureSkipTlsVerify=true \
    --set 'bootstrap.nodeServices={*}' \
    --set 'bootstrap.nodeMembers={sam:system:authenticated}' \
    --set gateway.enabled=true \
    --set gateway.className=cloud-provider-kind \
    --set gateway.adminRoute=true \
    --set router.hostPort=4501 \
    --set router.nodeSelector.sam-role=control-plane \
    --set router.useOidcToken=true \
    "$@"
}

# apply_dex <issuer> <console redirect URI>: Dex is an independent component, deployed
# from dex.yaml rather than the chart, with the URLs of the moment substituted in.
apply_dex() {
  DEX_ISSUER="$1" CONSOLE_REDIRECT_URI="$2" \
    envsubst '${DEX_ISSUER} ${CONSOLE_REDIRECT_URI}' < "${SCRIPT_DIR}/dex.yaml" \
    | kubectl --context "${KCTX}" -n "${NAMESPACE}" apply -f -
}

# logs: $1 = pane name (printed in-pane and set as the pane title); $2 = logs target.
logs() { echo "printf '\\033[1;36m==== %s ====\\033[0m\\n' '$1'; kubectl --context ${KCTX} -n ${NAMESPACE} logs -f $2; echo; echo '[$1 pane exited; press enter]'; read"; }

# tmuxs: tmux wrapper to ensure that bypass any tmux config the user might be using
tmuxs() { tmux -L samsocket -f /dev/null "$@"; }

show_cluster_logs() {
  tmuxs kill-session -t "${SESSION}" 2>/dev/null || true

  # Resolved here rather than inherited so `-l` on a running cluster gets the header too.
  local main_ip dex_ip
  main_ip="$(gateway_ip sam-mesh-gateway)"
  dex_ip="$(gateway_ip sam-mesh-dex-gateway)"

  tmuxs new-session -d -s "${SESSION}" -n mesh "$(logs control-plane 'deploy/sam-mesh-control-plane')" \; set -t "${SESSION}" destroy-unattached off
  tmuxs split-window -t "${SESSION}:0" "$(logs router 'statefulset/sam-mesh-router')"
  tmuxs set-option -t "${SESSION}" -g pane-border-status top
  tmuxs set-option -t "${SESSION}" -g pane-border-format ' #{pane_title} '
  tmuxs set-option -t "${SESSION}" status-position top
  tmuxs set-option -t "${SESSION}" status-left-length 250
  tmuxs set-option -t "${SESSION}" status-right ''
  tmuxs set-option -t "${SESSION}" status-left " console http://${main_ip}${CONSOLE_BASE_PATH}/  control plane http://${main_ip}  dex http://${dex_ip}/dex "

  # Title the tmux panes in creation order: control-plane, router.
  titles=(control-plane router)
  i=0
  for pane in $(tmuxs list-panes -t "${SESSION}:0" -F '#{pane_id}'); do
    tmuxs select-pane -t "$pane" -T "${titles[$i]}"
    i=$((i+1))
  done

  read -r -p "Press enter to show cluster logs…" _
  tmuxs attach-session -t "${SESSION}"
}


### MAIN ###


if [[ $# -gt 0 && "$1" != "-s" && "$1" != "-l" && "$1" != "-d" ]]; then
  echo "usage: $(basename "$0") [-s|-l|-d]" >&2
  exit 1
fi

if [[ "${1:-}" == "-l" ]]; then
  show_cluster_logs
  exit 0
fi

if [[ "${1:-}" == "-d" ]]; then
  teardown
  exit 0
fi

check_prereqs "${1:-}"

echo "== Creating kind cluster '${CLUSTER}' =="
kind create cluster --name "${CLUSTER}" --config "${SCRIPT_DIR}/kind-config.yaml"

echo "== Starting cloud-provider-kind =="
start_cloud_provider_kind

echo "== Building sam images =="
make docker-build-control-plane docker-build-router docker-build-node docker-build-sam-console
echo "== Loading sam images into kind =="
kind load docker-image --name "${CLUSTER}" "sam-control-plane:${IMAGE_TAG}" "sam-router:${IMAGE_TAG}" "sam-node:${IMAGE_TAG}" "sam-console:${IMAGE_TAG}"

# Apply the control plane and router, and wait until they accept connections
ISSUER="$(kubectl --context "${KCTX}" get --raw /.well-known/openid-configuration | jq -r .issuer)"
[[ -n "$ISSUER" ]] || { echo "could not determine cluster OIDC issuer" >&2; exit 1; }

# Dex's own address isn't known until its gateway has one, so phase 1 trusts only the
# cluster issuer and phase 2 prepends Dex.
CONTROL_PLANE_ISSUERS="${ISSUER}"

# The first audience is what the control plane reports as the OIDC client id, so it has to
# match Dex's static client.
ALLOWED_AUDIENCES="sam-console,sam-mesh-audience,sam-control-plane-audience"

# 00-namespace-rbac.yaml's envsubst reads this from the environment.
export NAMESPACE

echo "== Applying namespace and RBAC cluster rules =="
envsubst '${NAMESPACE}' < "${SCRIPT_DIR}/00-namespace-rbac.yaml" | kubectl --context "${KCTX}" apply -f -

echo "== Deploying SAM Mesh via Helm =="
deploy_chart

# The real URLs aren't known until Dex's gateway exists, so deploy it with placeholders
# first and rewire it below.
echo "== Deploying Dex =="
apply_dex "http://sam-mesh-dex:5556/dex" "http://127.0.0.1${CONSOLE_BASE_PATH}/auth/callback"

# The OIDC URLs are the gateway addresses, which only exist once the gateways do — so
# resolve them, then redeploy with the URLs everything must agree on.
echo "== Waiting for gateway LoadBalancer addresses =="
MAIN_IP="$(gateway_ip sam-mesh-gateway)"
DEX_IP="$(gateway_ip sam-mesh-dex-gateway)"
CONSOLE_URL="http://${MAIN_IP}${CONSOLE_BASE_PATH}/"
echo "control plane: http://${MAIN_IP}  console: ${CONSOLE_URL}  dex: http://${DEX_IP}"

OIDC_ISSUER="http://${DEX_IP}/dex"

echo "== Wiring the OIDC URLs into Dex =="
apply_dex "${OIDC_ISSUER}" "http://${MAIN_IP}${CONSOLE_BASE_PATH}/auth/callback"
# A config-only change doesn't roll the pods, and Dex reads its config at startup.
kubectl --context "${KCTX}" -n "${NAMESPACE}" rollout restart deployment/sam-mesh-dex
kubectl --context "${KCTX}" -n "${NAMESPACE}" rollout status deployment/sam-mesh-dex --timeout=180s

# The control plane discovers the issuer at startup and refuses to start if it can't, so
# prove a pod can reach the gateway address before pinning the mesh to it.
echo "== Checking Dex discovery from inside the cluster =="
# A pod left behind by an interrupted run fails the next one with AlreadyExists, which
# reads exactly like a routing failure.
kubectl --context "${KCTX}" -n "${NAMESPACE}" delete pod dex-discovery-check --ignore-not-found >/dev/null
kubectl --context "${KCTX}" -n "${NAMESPACE}" run dex-discovery-check \
  --rm -i --restart=Never --quiet --image=curlimages/curl:8.6.0 -- \
  curl -sf --retry 10 --retry-delay 2 --retry-connrefused --connect-timeout 5 --max-time 20 \
  "${OIDC_ISSUER}/.well-known/openid-configuration" >/dev/null || {
    echo "cannot reach ${OIDC_ISSUER} from inside the cluster; pods must be able to route to the cloud-provider-kind LoadBalancer addresses" >&2
    exit 1
  }

echo "== Wiring the OIDC URLs into the control plane =="
CONTROL_PLANE_ISSUERS="${OIDC_ISSUER},${ISSUER}"
deploy_chart

echo "== Waiting for database to be ready =="
kubectl --context "${KCTX}" -n "${NAMESPACE}" wait --for=condition=ready --timeout=180s pod -l app=sam-mesh-db
echo "== Waiting for control plane to be ready =="
# rollout status, not wait --for=available: every pod must serve the Dex issuer before
# the console reads it below.
kubectl --context "${KCTX}" -n "${NAMESPACE}" rollout status deployment/sam-mesh-control-plane --timeout=180s

# Policy seeding is handled automatically by the Helm chart bootstrap job, we just wait for it to complete.
echo "== Waiting for bootstrap job to complete =="
kubectl --context "${KCTX}" -n "${NAMESPACE}" wait --for=condition=complete --timeout=120s job/sam-mesh-bootstrap

echo "== Waiting for router to be ready =="
kubectl --context "${KCTX}" -n "${NAMESPACE}" wait --for=condition=ready --timeout=180s pod -l app=sam-mesh-router

# The console discovers the issuer from the control plane's /info once, at startup, so
# restart it now that the control plane serves the Dex issuer.
echo "== Restarting the console with the final issuer =="
kubectl --context "${KCTX}" -n "${NAMESPACE}" rollout restart deployment/sam-mesh-console
kubectl --context "${KCTX}" -n "${NAMESPACE}" rollout status deployment/sam-mesh-console --timeout=180s

echo
echo "Mesh up."
echo "  console:       ${CONSOLE_URL}"
echo "  control plane: http://${MAIN_IP}"
echo "  dex:           ${OIDC_ISSUER}"
echo
echo "To put a service on the mesh, deploy an example with charts/sam-node:"
echo "  ./development/deploy-kind-service.sh development/examples/calc-mcp"
echo "(it prints the docker build / kind load / helm install commands as it runs them)"
echo
echo "To drive the mesh, enroll a local node in another shell (it stays in the foreground):"
echo "  make build && make kind-local-node"
echo "then call its MCP API on 127.0.0.1:9099:"
echo "  ./bin/mcp-client -url http://127.0.0.1:9099/mcp -token devtoken -tool get_mesh_info -args '{}'"
echo "  ./bin/mcp-client -url http://127.0.0.1:9099/mcp -token devtoken -tool find_remote_tools -args '{}'"

if [[ "${1:-}" != "-s" ]]; then
  show_cluster_logs
fi
