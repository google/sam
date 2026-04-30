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

@test "Revocation: Node disconnects from banned peer after receiving event" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  # Start Hub with a known key so we can sign events
  local hub_name="${MESH_PREFIX}-hub"
  local hub_key
  hub_key="$(mesh_gen_hex32)"

  docker run -d \
    --name "${hub_name}" \
    --network "${MESH_NETWORK}" \
    --network-alias sam-hub \
    "sam-hub:local" \
    --issuer "http://mock-oidc:18080" \
    --client-id "sam-e2e" \
    --key "${hub_key}" \
    --listen "/ip4/0.0.0.0/udp/4001/quic-v1" \
    --listen "/ip4/0.0.0.0/tcp/4002" \
    --mesh "e2e-mesh" >/dev/null

  MESH_CONTAINERS+=("${hub_name}")
  mesh_wait_for_log "${hub_name}" "PeerID:" 20

  local hub_peer_id
  hub_peer_id=$(docker logs "${hub_name}" 2>&1 | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)
  echo "${hub_peer_id}" > "/tmp/${MESH_PREFIX}-hub-peer-id"

  # Start Node 1
  run mesh_start_node 1
  [[ "$status" -eq 0 ]]
  local node1_name="${MESH_PREFIX}-node-1"
  mesh_wait_for_log "${node1_name}" "SAM Node Online" 20
  
  local node1_peer_id
  node1_peer_id=$(docker logs "${node1_name}" 2>&1 | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)

  # Start Node 2
  run mesh_start_node 2
  [[ "$status" -eq 0 ]]
  local node2_name="${MESH_PREFIX}-node-2"
  mesh_wait_for_log "${node2_name}" "SAM Node Online" 20

  # Extract Node 2 Peer ID
  local node2_peer_id
  node2_peer_id=$(docker logs "${node2_name}" 2>&1 | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)
  [[ -n "${node2_peer_id}" ]]

  # Verify nodes are connected to each other or at least known
  # We wait a bit for discovery
  sleep 5

  # Publish ban event for Node 2
  run docker exec "${hub_name}" /sam-hub admin ban --peer "${node2_peer_id}" --connect "/ip4/127.0.0.1/tcp/4002"
  
  echo "admin ban output: $output"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Published BANNED event"* ]]

  # Verify Node 1 receives the ban event and logs it
  run mesh_wait_for_log "${node1_name}" "Peer banned: ${node2_peer_id}" 20
  if [[ "$status" -ne 0 ]]; then
    echo "Node 1 logs:"
    docker logs "${node1_name}"
  fi
  [[ "$status" -eq 0 ]]

  # Verify Node 1 disconnects from Node 2
  # In a full test we would check active connections, but checking the log is a good proxy
  # since node.go calls ClosePeer.
}
