#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
  if ! mesh_require_docker; then
    skip "docker not available or daemon not running"
  fi

  if [[ ! -x "./bin/sam-node" || ! -x "./bin/sam-hub" || ! -x "./bin/mcp-client" ]]; then
    skip "missing binaries; run: make build"
  fi

  mesh_setup_env
}

teardown() {
  mesh_cleanup_env
  # Cleanup any additional containers started in the test
  docker rm -f http-service sse-client >/dev/null 2>&1 || true
}

@test "Datapath: HTTP and Stdio services are reachable across nodes" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  # Start Hub
  mesh_start_hub
  local hub_name="${MESH_PREFIX}-hub"
  local hub_peer_id
  hub_peer_id=$(cat "/tmp/${MESH_PREFIX}-hub-peer-id")

  # Start Node 1
  echo "[$(date +%T)] Starting Node 1"
  run mesh_start_node 1 "--discovery-interval 100ms --log-level debug"
  [[ "$status" -eq 0 ]]
  local node1_name="${MESH_PREFIX}-node-1"
  mesh_wait_for_log "${node1_name}" "SAM Node Online" 20
  mesh_wait_for_mcp_ready 1 20
  
  local node1_peer_id
  node1_peer_id=$(docker logs "${node1_name}" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')

  # Start Node 2
  echo "[$(date +%T)] Starting Node 2"
  run mesh_start_node 2 "--discovery-interval 100ms --log-level debug"
  [[ "$status" -eq 0 ]]
  local node2_name="${MESH_PREFIX}-node-2"
  mesh_wait_for_log "${node2_name}" "SAM Node Online" 20
  mesh_wait_for_mcp_ready 2 20

  local node2_peer_id
  node2_peer_id=$(docker logs "${node2_name}" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')

  # Explicitly connect Node 1 to Node 2 (DHT auto-discovery is slow/unreliable in this E2E setup)
  echo "[$(date +%T)] Explicitly connecting Node 1 to Node 2"
  local node2_addr="/dns4/sam-node-2/tcp/5002/p2p/${node2_peer_id}"
  run docker run --rm --network "${MESH_NETWORK}" -v "$(pwd)/bin/mcp-client:/mcp-client" python:3.12 /mcp-client -url "http://sam-node-1:8080/mcp/events" -tool "connect_peer" -args "{\"peer_addr\":\"${node2_addr}\"}"
  [[ "$status" -eq 0 ]]

  # Verify connection
  mesh_wait_for_peer_connection 1 "${node2_peer_id}" 20
  [[ "$status" -eq 0 ]]

  # 1. Setup HTTP Service on Node 1 side
  # Start a dummy HTTP server in a separate container
  echo "[$(date +%T)] Starting dummy HTTP service"
  docker run -d \
    --name http-service \
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
  MESH_CONTAINERS+=("http-service")

  # Register HTTP service on Node 1
  echo "[$(date +%T)] Registering HTTP service on Node 1"
  run docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "
import urllib.request
import json

data = {
    \"service\": {
        \"type\": 1,
        \"name\": \"http-tool\",
        \"description\": \"test http service\"
    },
    \"targetUrl\": \"http://http-service:8000\"
}

req = urllib.request.Request(
    \"http://sam-node-1:8080/sam/service/register\",
    data=json.dumps(data).encode(\"utf-8\"),
    headers={
        \"Authorization\": \"Bearer secret-token\",
        \"Content-Type\": \"application/json\"
    }
)
with urllib.request.urlopen(req) as response:
    print(response.read().decode(\"utf-8\"))
"
  echo "Register HTTP output: $output"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Service registered"* ]]

  # 2. Setup Stdio Service on Node 2 side
  # Register Stdio service (cat) on Node 2
  echo "[$(date +%T)] Registering Stdio service on Node 2"
  run docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "
import urllib.request
import json

data = {
    'service': {
        'type': 1,
        'name': 'stdio-tool',
        'description': 'test stdio service'
    },
    'command': {
        'command': ['sh', '-c', 'sleep 1; cat']
    }
}

req = urllib.request.Request(
    'http://sam-node-2:8080/sam/service/register',
    data=json.dumps(data).encode('utf-8'),
    headers={
        'Authorization': 'Bearer secret-token',
        'Content-Type': 'application/json'
    }
)
with urllib.request.urlopen(req) as response:
    print(response.read().decode('utf-8'))
"
  if [[ "$status" -ne 0 ]]; then
    echo "Node 2 logs:"
    docker logs "${node2_name}"
  fi
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Service registered"* ]]

  # Wait for DHT propagation
  sleep 2

  # 3. Test HTTP Datapath: Node 2 calls Node 1's HTTP service
  echo "[$(date +%T)] Testing HTTP Datapath from Node 2 to Node 1"
  run docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "
import urllib.request
req = urllib.request.Request(
    \"http://sam-node-2:8080/sam/${node1_peer_id}/mcp/http-tool/\",
    headers={\"Authorization\": \"Bearer secret-token\"}
)
with urllib.request.urlopen(req) as response:
    print(response.read().decode(\"utf-8\"))
"
  echo "HTTP Call output: $output"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"{\"status\":\"success\"}"* ]]

  # 4. Test Stdio Datapath: Node 1 calls Node 2's Stdio service
  echo "[$(date +%T)] Testing Stdio Datapath from Node 1 to Node 2"
  
  # Start SSE client in background on Node 1 targeting Node 2's service
  docker run -d \
    --name sse-client \
    --network "${MESH_NETWORK}" \
    python:3.12 python3 -c "
import urllib.request
req = urllib.request.Request(
    \"http://sam-node-1:8080/sam/${node2_peer_id}/mcp/stdio-tool/\",
    headers={\"Authorization\": \"Bearer secret-token\"}
)
try:
    with urllib.request.urlopen(req) as response:
        for line in response:
            print(line.decode(\"utf-8\").strip(), flush=True)
except Exception as e:
    print(f\"Error: {e}\", flush=True)
"
  MESH_CONTAINERS+=("sse-client")

  # Wait a bit for SSE stream to establish
  sleep 1

  # Send message via POST from Node 1 to Node 2's service
  test_message="{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}"
  run docker run --rm --network "${MESH_NETWORK}" -e MSG="${test_message}" python:3.12 python3 -c "
import urllib.request
import os
req = urllib.request.Request(
    \"http://sam-node-1:8080/sam/${node2_peer_id}/mcp/stdio-tool/\",
    data=os.environ['MSG'].encode('utf-8'),
    headers={
        \"Authorization\": \"Bearer secret-token\",
        \"Content-Type\": \"application/json\"
    }
)
with urllib.request.urlopen(req) as response:
    print(response.status)
"
  echo "POST status: $output"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"200"* ]]

  # Wait for message to echo back
  sleep 1

  # Check SSE client logs for the echoed message
  run docker logs sse-client
  echo "SSE client logs: $output"
  [[ "$output" == *"data: ${test_message}"* ]]
}
