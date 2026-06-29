#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
  mesh_setup_env
}

teardown() {
  if [[ "${BATS_TEST_COMPLETED:-0}" -ne 1 ]]; then
    echo "Node 1 logs on failure (filtered):"
    docker logs "${MESH_PREFIX}-node-1" 2>&1 | grep -i -E 'mcp|request|error|fatal|panic' || true
  fi
  mesh_cleanup_env
}

@test "Python SDK: Connect, get tools, and call tool" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  run mesh_start_node 1 "--log-level debug"
  [[ "$status" -eq 0 ]]
  
  local node1_name="${MESH_PREFIX}-node-1"
  mesh_wait_for_log "${node1_name}" "SAM Node Online" 20
  mesh_wait_for_mcp_ready 1 20

  # Use the Python SDK to interact with the node
  run docker run --rm \
    --network "${MESH_NETWORK}" \
    -v "$(pwd)/sam-mcp-python:/sam-mcp-python" \
    -e PYTHONPATH=/sam-mcp-python/src \
    -e SAM_API_TOKEN=secret-token \
    python:3.12 \
    bash -c 'pip install mcp httpx && python3 /sam-mcp-python/test_client.py'
  echo "Python SDK output: $output"
  if [[ "$status" -ne 0 ]]; then
    echo "Node 1 logs:"
    docker logs "${node1_name}"
  fi
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"TOOLS_COUNT:"* ]]
  [[ "$output" == *"CALL_RESULT:"* ]]
}
