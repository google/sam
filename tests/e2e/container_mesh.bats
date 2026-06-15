#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
  mesh_setup_env
  mkdir -p tests/e2e/logs
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
  mesh_cleanup_env
}

@test "container framework starts hub and multiple nodes" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  local node_count=5
  local i
  for i in $(seq 1 "$node_count"); do
    run mesh_start_node "$i"
    [[ "$status" -eq 0 ]]
    sleep 2
  done

  # Verify every container remains healthy enough to keep the process running.
  run mesh_assert_container_running "${MESH_PREFIX}-hub"
  [[ "$status" -eq 0 ]]

  for i in $(seq 1 "$node_count"); do
    run mesh_assert_container_running "${MESH_PREFIX}-node-${i}"
    [[ "$status" -eq 0 ]]
  done

  # Wait for MCP readiness on each node.
  for i in $(seq 1 "$node_count"); do
    run mesh_wait_for_mcp_ready "${i}" 20
    [[ "$status" -eq 0 ]]
  done

  # Verify connected peer count via MCP (wait for full mesh).
  for i in $(seq 1 "$node_count"); do
    run mesh_wait_for_node_count "${i}" $((node_count - 1)) 60
    [[ "$status" -eq 0 ]]
  done
}
