#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
  if ! mesh_require_docker; then
    skip "docker not available or daemon not running"
  fi

  if [[ ! -x "./bin/sam-node" || ! -x "./bin/sam-hub" ]]; then
    skip "missing binaries; run: make build"
  fi

  mesh_build_runtime_image
  mesh_setup_env
}

teardown() {
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
  done

  # Verify every container remains healthy enough to keep the process running.
  run mesh_assert_container_running "${MESH_PREFIX}-hub"
  [[ "$status" -eq 0 ]]

  for i in $(seq 1 "$node_count"); do
    run mesh_assert_container_running "${MESH_PREFIX}-node-${i}"
    [[ "$status" -eq 0 ]]
  done
}
