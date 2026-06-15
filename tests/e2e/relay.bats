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

@test "node starts with --enable-relay=true and logs message" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  # Start node with relay flag
  run mesh_start_node "1" "--enable-relay=true --log-level=debug"
  [[ "$status" -eq 0 ]]

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

  docker network connect --alias sam-hub "${MESH_NETWORK_2}" "${MESH_PREFIX}-hub"
  docker network connect --alias mock-oidc "${MESH_NETWORK_2}" "${MESH_PREFIX}-oidc"

  run mesh_start_node "1" "--enable-relay=true --log-level=debug"
  [[ "$status" -eq 0 ]]

  OLD_NET=$MESH_NETWORK
  MESH_NETWORK=$MESH_NETWORK_2
  run mesh_start_node "2" "--log-level=debug"
  [[ "$status" -eq 0 ]]
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

  docker network rm "${MESH_NETWORK_2}" >/dev/null 2>&1 || true
}
