#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
  if ! mesh_require_docker; then
    skip "docker not available or daemon not running"
  fi

  if [[ ! -x "./bin/sam-node" || ! -x "./bin/sam-hub" ]]; then
    skip "missing binaries; run: make build"
  fi

  mesh_setup_env
}

teardown() {
  if [[ "${BATS_TEST_COMPLETED:-0}" -ne 1 ]]; then
    echo "Node 1 logs on failure (filtered):"
    docker logs "${MESH_PREFIX}-node-1" 2>&1 | grep -i -E 'mcp|request|error|fatal|panic' || true
  fi
  mesh_cleanup_env
}

@test "Docs Snippets: agent_demo.py runs successfully" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  run mesh_start_node 1 "--discovery-interval 100ms --log-level debug"
  [[ "$status" -eq 0 ]]

  local node1_name="${MESH_PREFIX}-node-1"
  mesh_wait_for_log "${node1_name}" "SAM Node Online" 20
  mesh_wait_for_mcp_ready 1 20

  # Run the agent_demo.py snippet inside a container
  run docker run --rm \
    --network "${MESH_NETWORK}" \
    -v "$(pwd)/sam-mcp-python:/sam-mcp-python" \
    -v "$(pwd)/docs/snippets:/snippets" \
    -e PYTHONPATH=/sam-mcp-python/src \
    -e SAM_MCP_URL="http://sam-node-1:8080/mcp/events" \
    python:3.12 \
    bash -c 'pip install mcp httpx && python3 /snippets/agent_demo.py'

  echo "agent_demo.py output: $output"

  if [[ "$status" -ne 0 ]]; then
    echo "Node 1 logs:"
    docker logs "${node1_name}"
  fi

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Connecting to SAM Node at"* ]]
  [[ "$output" == *"Discovered"* ]]
  [[ "$output" == *"Calling get_mesh_info tool..."* ]]
  [[ "$output" == *"Result:"* ]]
}
