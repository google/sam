#!/usr/bin/env bats

load "lib/container_mesh.bash"

CALC_MCP_IMAGE="sam-calc-mcp:local"

build_calc_mcp_image() {
  if ! docker image inspect "${CALC_MCP_IMAGE}" >/dev/null 2>&1; then
    docker build -t "${CALC_MCP_IMAGE}" \
      -f tests/e2e/docker/calc-mcp/Dockerfile \
      tests/e2e/docker/calc-mcp >/dev/null
  fi
}

start_calc_mcp() {
  local name="${MESH_PREFIX}-calc-mcp"
  docker run -d \
    --name "${name}" \
    --network "${MESH_NETWORK}" \
    --network-alias calc-mcp \
    "${CALC_MCP_IMAGE}" >/dev/null
  MESH_CONTAINERS+=("${name}")
  mesh_wait_for_log "${name}" "Uvicorn running on" 20
}

setup() {
  if ! mesh_require_docker; then
    skip "docker not available or daemon not running"
  fi
  mesh_setup_env
  build_calc_mcp_image
}

teardown() {
  mesh_cleanup_env
}

@test "find_remote_tools surfaces aggregated tools from a remote peer" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  mesh_start_hub

  echo "[$(date +%T)] Starting Node 1"
  run mesh_start_node 1 "--discovery-interval 100ms --log-level debug"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_log "${MESH_PREFIX}-node-1" "SAM Node Online" 60
  mesh_wait_for_mcp_ready 1 20

  echo "[$(date +%T)] Starting calc-mcp backend"
  start_calc_mcp

  echo "[$(date +%T)] Starting Node 2 with calculator service"
  run mesh_start_node 2 \
    "--discovery-interval 100ms --log-level debug" \
    "tests/e2e/docker/calc-mcp/sam-node-config.yaml"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_log "${MESH_PREFIX}-node-2" "SAM Node Online" 20
  mesh_wait_for_mcp_ready 2 20

  local node2_peer_id
  node2_peer_id=$(docker logs "${MESH_PREFIX}-node-2" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')

  echo "[$(date +%T)] Connecting Node 1 to Node 2"
  local node2_addr="/dns4/sam-node-2/tcp/5002/p2p/${node2_peer_id}"
  run docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://sam-node-1:8080/mcp/events" -tool "connect_peer" -args "{\"peer_addr\":\"${node2_addr}\"}"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_peer_connection 1 "${node2_peer_id}" 20

  echo "[$(date +%T)] Calling find_remote_tools from Node 1, targeting Node 2"
  run docker run --rm --network "${MESH_NETWORK}" \
    "${MESH_RUNTIME_IMAGE}" mcp-client \
    -url "http://sam-node-1:8080/mcp/events" \
    -tool "find_remote_tools" \
    -args "{\"peer_id\":\"${node2_peer_id}\"}"
  echo "find_remote_tools output: $output"
  [[ "$status" -eq 0 ]]

  # mcp-client prints each text-content line; the catalog JSON is the last non-empty line.
  local catalog
  catalog=$(echo "$output" | tail -n 1)

  local match_count
  match_count=$(echo "$catalog" | jq --arg pid "${node2_peer_id}" '
    [.[] | select(.peer_id == $pid
                 and (.tool_name | startswith("calculator.")))] | length
  ')
  echo "Matching calculator tool entries: ${match_count}"
  [[ "${match_count}" -ge 1 ]]
}

@test "call_remote_tool invokes an aggregated hosted-service tool end to end" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  mesh_start_hub

  echo "[$(date +%T)] Starting Node 1"
  run mesh_start_node 1 "--discovery-interval 100ms --log-level debug"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_log "${MESH_PREFIX}-node-1" "SAM Node Online" 60
  mesh_wait_for_mcp_ready 1 20

  echo "[$(date +%T)] Starting calc-mcp backend"
  start_calc_mcp

  echo "[$(date +%T)] Starting Node 2 with calculator service"
  run mesh_start_node 2 \
    "--discovery-interval 100ms --log-level debug" \
    "tests/e2e/docker/calc-mcp/sam-node-config.yaml"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_log "${MESH_PREFIX}-node-2" "SAM Node Online" 20
  mesh_wait_for_mcp_ready 2 20

  local node2_peer_id
  node2_peer_id=$(docker logs "${MESH_PREFIX}-node-2" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')

  echo "[$(date +%T)] Connecting Node 1 to Node 2"
  local node2_addr="/dns4/sam-node-2/tcp/5002/p2p/${node2_peer_id}"
  run docker run --rm --network "${MESH_NETWORK}" \
    "${MESH_RUNTIME_IMAGE}" mcp-client \
    -url "http://sam-node-1:8080/mcp/events" \
    -tool "connect_peer" \
    -args "{\"peer_addr\":\"${node2_addr}\"}"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_peer_connection 1 "${node2_peer_id}" 20

  echo "[$(date +%T)] Calling call_remote_tool for calculator.add"
  local call_args
  call_args="{\"peer_id\":\"${node2_peer_id}\",\"tool_name\":\"calculator.add\",\"arguments\":\"{\\\"a\\\":2,\\\"b\\\":3}\"}"
  run docker run --rm --network "${MESH_NETWORK}" \
    "${MESH_RUNTIME_IMAGE}" mcp-client \
    -url "http://sam-node-1:8080/mcp/events" \
    -tool "call_remote_tool" \
    -args "${call_args}"
  echo "call_remote_tool output: $output"
  [[ "$status" -eq 0 ]]

  # calc-mcp returns add(2,3)=5 as a TextContent string; "5" must appear in the response.
  [[ "$output" == *"5"* ]]
}
