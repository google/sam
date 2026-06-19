#!/usr/bin/env bats

setup() {
  CLUSTER_NAME="sam-wi-test-$RANDOM"
  KUBECONTEXT="kind-${CLUSTER_NAME}"
  
  # Create Kind cluster with 2 worker nodes so we can use hostPort
  cat <<KIND | kind create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
KIND
  
  # Load images into Kind
  kind load docker-image sam-hub:local --name "${CLUSTER_NAME}"
  kind load docker-image sam-node:local --name "${CLUSTER_NAME}"
}

teardown() {
  echo "=== Hub Logs ==="
  kubectl --context="${KUBECONTEXT}" logs -l app=sam-hub --tail=-1 || true
  echo "=== Node Logs ==="
  kubectl --context="${KUBECONTEXT}" logs -l app=sam-node --tail=-1 || true
  kind delete cluster --name "${CLUSTER_NAME}"
  docker rm -f external-sam-node >/dev/null 2>&1 || true
}

k8s_wait_for_log() {
  local pod="$1"
  local needle="$2"
  local timeout_s="${3:-20}"
  local i
  for ((i=0; i<timeout_s*10; i++)); do
    if kubectl --context="${KUBECONTEXT}" logs "${pod}" 2>&1 | grep -E -q "${needle}"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

docker_wait_for_log() {
  local container="$1"
  local needle="$2"
  local timeout_s="${3:-20}"
  local i
  for ((i=0; i<timeout_s*10; i++)); do
    if docker logs "${container}" 2>&1 | grep -E -q "${needle}"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

deploy_mesh() {
  # 1. Get the issuer URL
  local issuer
  issuer=$(kubectl --context="${KUBECONTEXT}" get --raw /.well-known/openid-configuration | jq -r .issuer)
  [[ -n "${issuer}" ]]

  # 1.5. Grant anonymous access to OIDC discovery
  kubectl --context="${KUBECONTEXT}" apply -f tests/e2e/fixtures/allow-anonymous-oidc.yaml

  # 2. Deploy Hub
  export ISSUER="${issuer}"
  envsubst < tests/e2e/fixtures/sam-hub.yaml | kubectl --context="${KUBECONTEXT}" apply -f -

  # Wait for Hub to be ready
  kubectl --context="${KUBECONTEXT}" rollout status statefulset/sam-hub --timeout=60s

  # Get Hub PeerID
  k8s_wait_for_log "sam-hub-0" "PeerID:" 20
  local hub_peer_id
  hub_peer_id=$(kubectl --context="${KUBECONTEXT}" logs "sam-hub-0" | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1 || true)
  [[ -n "${hub_peer_id}" ]]

  # 3. Deploy Node
  kubectl --context="${KUBECONTEXT}" create serviceaccount sam-node-sa || true

  kubectl --context="${KUBECONTEXT}" apply -f tests/e2e/fixtures/sam-node.yaml

  # Wait for Node to be ready
  kubectl --context="${KUBECONTEXT}" wait --for=condition=available deployment/sam-node --timeout=60s
}

@test "Workload Identity Federation in Kind" {
  deploy_mesh

  # Verify enrollment
  local pod_name
  pod_name=$(kubectl --context="${KUBECONTEXT}" get pods -l app=sam-node -o jsonpath='{.items[0].metadata.name}')
  
  k8s_wait_for_log "${pod_name}" "SAM Node Online|Successfully enrolled" 30
}

@test "Local SAM agent connects to cluster hub and uses relay" {
  deploy_mesh

  # Get IP of nodes running sam-hub pods
  NODE0_IP=$(kubectl --context="${KUBECONTEXT}" get pod sam-hub-0 -o jsonpath='{.status.hostIP}')
  NODE1_IP=$(kubectl --context="${KUBECONTEXT}" get pod sam-hub-1 -o jsonpath='{.status.hostIP}')

  # Start external node in a docker container attached to kind network
  # We use the sam-node:local image and mount the token
  kubectl --context="${KUBECONTEXT}" create token sam-node-sa --duration=1h --audience="sam-mesh-audience" > /tmp/sam-token
  
  # Run the node using docker
  # We add /etc/hosts entries for sam-hub.default.svc.cluster.local
  docker run -d --name external-sam-node --network kind \
    --add-host "sam-hub.default.svc.cluster.local:$NODE0_IP" \
    --add-host "sam-hub.default.svc.cluster.local:$NODE1_IP" \
    -v /tmp/sam-token:/var/run/secrets/tokens/sam-token \
    sam-node:local run \
    --hub "http://sam-hub.default.svc.cluster.local:9090" \
    --jwt-path "/var/run/secrets/tokens/sam-token" \
    --api-token "secret-token" \
    --bind-addr "0.0.0.0:8080" \
    --allow-loopback

  # Wait for external node to be ready
  if ! docker_wait_for_log external-sam-node "SAM Node Online|Successfully enrolled" 30; then
    echo "external-sam-node failed to start or connect. Logs:"
    docker logs external-sam-node
    return 1
  fi
  
  # Register a service on the first cluster node
  local pod_name
  pod_name=$(kubectl --context="${KUBECONTEXT}" get pods -l app=sam-node -o jsonpath='{.items[0].metadata.name}')
  
  # Wait for the cluster node to log its PeerID
  k8s_wait_for_log "${pod_name}" "PeerID:" 20
  local cluster_node_peer_id
  cluster_node_peer_id=$(kubectl --context="${KUBECONTEXT}" logs "${pod_name}" | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r' || true)

  # Port forward cluster node to register a service from the host
  kubectl --context="${KUBECONTEXT}" port-forward "${pod_name}" 8081:8080 &
  PF_NODE_PID=$!
  
  local i
  for ((i=0; i<50; i++)); do
    if nc -z 127.0.0.1 8081 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  # Register a service on the cluster node that points to its own /healthz endpoint
  python3 -c "
import urllib.request
import json
data = {
    'service': {
        'type': 3,
        'name': 'echo-tool',
        'description': 'test'
    },
    'target_url': 'http://127.0.0.1:8080/healthz'
}
req = urllib.request.Request(
    'http://127.0.0.1:8081/sam/service/register',
    data=json.dumps(data).encode('utf-8'),
    headers={
        'Authorization': 'Bearer secret-token',
        'Content-Type': 'application/json'
    }
)
with urllib.request.urlopen(req) as response:
    print(response.read().decode('utf-8'))
"

  # The external node will use its sidecar egress proxy to talk to the cluster node over the mesh.
  echo "Testing mesh datapath..."
  local output
  local i
  for ((i=0; i<60; i++)); do
    output=$(docker run --rm --network container:external-sam-node alpine wget -q -O- --timeout=2 --header="Authorization: Bearer secret-token" "http://127.0.0.1:8080/sam/${cluster_node_peer_id}/a2a/echo-tool" || true)
    if [ "$output" == "OK" ]; then
      break
    fi
    sleep 1
  done
  
  if [ "$output" != "OK" ]; then
    echo "Expected 'OK', got '$output'"
    echo "=== External Node Logs ==="
    docker logs external-sam-node || true
    return 1
  fi

  # Cleanup
  kill $PF_NODE_PID || true
  docker rm -f external-sam-node || true
}
