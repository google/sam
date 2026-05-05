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
  mesh_cleanup_env
}

@test "Key Rotation: Node receives rotation event and remains functional" {
  run mesh_start_mock_oidc
  echo "mock_oidc status: $status, output: $output"
  [[ "$status" -eq 0 ]]

  # Start Hub with rotation enabled
  local hub_name="${MESH_PREFIX}-hub"
  local key
  key="$(mesh_gen_hex32)"

  docker run -d \
    --name "${hub_name}" \
    --network "${MESH_NETWORK}" \
    --network-alias sam-hub \
    "sam-hub:local" \
    --issuer "http://mock-oidc:18080" \
    --client-id "sam-e2e" \
    --key "${key}" \
    --listen "/ip4/0.0.0.0/udp/4001/quic-v1" \
    --listen "/ip4/0.0.0.0/tcp/4002" \
    --external-multiaddr "/dns4/sam-hub/tcp/4002" \
    --mesh "e2e-mesh" \
    --key-rotation-interval 5s >/dev/null

  MESH_CONTAINERS+=("${hub_name}")
  mesh_wait_for_log "${hub_name}" "PeerID:" 20

  local hub_peer_id
  hub_peer_id=$(docker logs "${hub_name}" 2>&1 | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)
  echo "${hub_peer_id}" > "/tmp/${MESH_PREFIX}-hub-peer-id"

  # Start Node
  run mesh_start_node 1
  [[ "$status" -eq 0 ]]

  local node_name="${MESH_PREFIX}-node-1"
  mesh_wait_for_log "${node_name}" "SAM Node Online" 20

  # Wait for rotation
  sleep 10

  # Verify Node received rotation event
  run mesh_wait_for_log "${node_name}" "Key rotation received" 10
  if [[ "$status" -ne 0 ]]; then
    echo "Node logs:"
    docker logs "${node_name}"
  fi
  [[ "$status" -eq 0 ]]

  # Verify node is still running
  run mesh_assert_container_running "${node_name}"
  [[ "$status" -eq 0 ]]
}
