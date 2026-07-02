#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
  mesh_setup_env
  CLEANUP_NETWORKS=()
  DISCONNECT_CONTAINERS=()
}

teardown() {
  if [[ "${BATS_TEST_COMPLETED:-0}" -ne 1 ]]; then
    mkdir -p tests/e2e/logs
    local ids
    ids="$(docker ps -aq --filter "name=mesh-")"
    for id in ${ids}; do
      local name
      name="$(docker inspect -f '{{.Name}}' "${id}" | tr -d '/')"
      docker logs "${id}" > "tests/e2e/logs/${name}.log" 2>&1 || true
    done
  fi

  local item
  for item in "${DISCONNECT_CONTAINERS[@]}"; do
    local container="${item%%:*}"
    local net="${item#*:}"
    docker network disconnect "${net}" "${container}" >/dev/null 2>&1 || true
  done
  DISCONNECT_CONTAINERS=()

  mesh_cleanup_env
  local net
  for net in "${CLEANUP_NETWORKS[@]}"; do
    docker network rm "${net}" >/dev/null 2>&1 || true
  done
  CLEANUP_NETWORKS=()
}

@test "node starts with --enable-relay=true and logs message" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  # Start node with relay flag
  mesh_start_node "1" "--enable-relay=true --log-level=debug"

  # Wait for log message
  run mesh_wait_for_log "${MESH_PREFIX}-node-1" "Enabling Relay Service" 20
  [[ "$status" -eq 0 ]]
}

@test "nodes in isolated networks discover and connect via relay" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  local MESH_NETWORK_2="${MESH_PREFIX}-2-net"
  docker network create "${MESH_NETWORK_2}"
  CLEANUP_NETWORKS+=("${MESH_NETWORK_2}")

  local hub_node
  hub_node=$(kubectl --context="${KUBECONTEXT}" get pod sam-hub-0 -o jsonpath='{.spec.nodeName}')
  local oidc_node
  oidc_node=$(kubectl --context="${KUBECONTEXT}" get pod -l app=mock-oidc -o jsonpath='{.items[0].spec.nodeName}')

  docker network connect "${MESH_NETWORK_2}" "${hub_node}"
  DISCONNECT_CONTAINERS+=("${hub_node}:${MESH_NETWORK_2}")
  if [[ "${oidc_node}" != "${hub_node}" ]]; then
    docker network connect "${MESH_NETWORK_2}" "${oidc_node}"
    DISCONNECT_CONTAINERS+=("${oidc_node}:${MESH_NETWORK_2}")
  fi

  mesh_start_node "1" "--enable-relay=true --log-level=debug"

  OLD_NET=$MESH_NETWORK
  MESH_NETWORK=$MESH_NETWORK_2
  mesh_start_node "2" "--log-level=debug"
  MESH_NETWORK=$OLD_NET

  run mesh_wait_for_log "${MESH_PREFIX}-node-1" "PeerID:" 20
  [[ "$status" -eq 0 ]]
  run mesh_wait_for_log "${MESH_PREFIX}-node-2" "PeerID:" 20
  [[ "$status" -eq 0 ]]

  # Node 1 should eventually see 1 peer (node 2) besides the hub
  run mesh_wait_for_node_count "1" 1 30
  [[ "$status" -eq 0 ]]

  # Node 2 should eventually see 1 peer (node 1) besides the hub
  OLD_NET=$MESH_NETWORK
  MESH_NETWORK=$MESH_NETWORK_2
  run mesh_wait_for_node_count "2" 1 30
  [[ "$status" -eq 0 ]]
  MESH_NETWORK=$OLD_NET

  local node1_peer_id
  node1_peer_id=$(docker logs "${MESH_PREFIX}-node-1" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')

  # 1. Setup HTTP Service on Node 1 side (default network)
  docker run -d \
    --name "${MESH_PREFIX}-http-service" \
    --network "${MESH_NETWORK}" \
    python:3.12 python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
class S(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(b"{\"status\":\"success\"}")
HTTPServer(("0.0.0.0", 8000), S).serve_forever()
'
  MESH_CONTAINERS+=("${MESH_PREFIX}-http-service")

  # Wait for http-service to be listening
  local i
  for ((i=0; i<30; i++)); do
    if docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "import urllib.request; urllib.request.urlopen('http://${MESH_PREFIX}-http-service:8000')" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  # Register HTTP service on Node 1
  run docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "
import urllib.request
import json

data = {
    \"service\": {
        \"type\": \"SERVICE_TYPE_MCP\",
        \"name\": \"http-tool\",
        \"description\": \"test http service\"
    },
    \"targetUrl\": \"http://${MESH_PREFIX}-http-service:8000\"
}

req = urllib.request.Request(
    \"http://${MESH_PREFIX}-node-1:8080/sam/service/register\",
    data=json.dumps(data).encode('utf-8'),
    headers={
        \"Content-Type\": \"application/json\",
        \"Authorization\": \"Bearer secret-token\"
    },
    method=\"POST\"
)
with urllib.request.urlopen(req) as response:
    print(response.read().decode('utf-8'))
"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Service registered"* ]]

  # 2. Test HTTP Datapath: Node 2 calls Node 1's HTTP service via Node 2's egress proxy (isolated network 2)
  for ((i=0; i<15; i++)); do
    run docker run --rm --network "${MESH_NETWORK_2}" python:3.12 python3 -c "
import urllib.request
req = urllib.request.Request(
    \"http://${MESH_PREFIX}-node-2:8080/sam/${node1_peer_id}/mcp/http-tool/\",
    headers={\"Authorization\": \"Bearer secret-token\"}
)
with urllib.request.urlopen(req) as response:
    print(response.read().decode(\"utf-8\"))
"
    if [[ "$status" -eq 0 ]] && [[ "$output" == *"{\"status\":\"success\"}"* ]]; then
      break
    fi
    sleep 1
  done

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"{\"status\":\"success\"}"* ]]

  docker network rm "${MESH_NETWORK_2}" >/dev/null 2>&1 || true
}
