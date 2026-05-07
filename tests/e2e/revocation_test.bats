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
    --mesh "e2e-mesh" \
    --admin-token "e2e-token" \
    --log-level debug >/dev/null

  MESH_CONTAINERS+=("${hub_name}")
  mesh_wait_for_log "${hub_name}" "PeerID:" 20

  local hub_peer_id
  hub_peer_id=$(docker logs "${hub_name}" 2>&1 | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)
  echo "${hub_peer_id}" > "/tmp/${MESH_PREFIX}-hub-peer-id"

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

  # Extract Node 2 Peer ID
  local node2_peer_id
  node2_peer_id=$(docker logs "${node2_name}" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')
  [[ -n "${node2_peer_id}" ]]

  # Explicitly connect Node 1 to Node 2
  echo "[$(date +%T)] Explicitly connecting Node 1 to Node 2"
  local node2_addr="/dns4/sam-node-2/tcp/5002/p2p/${node2_peer_id}"
  run docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://sam-node-1:8080/mcp/events" -tool "connect_peer" -args "{\"peer_addr\":\"${node2_addr}\"}"
  [[ "$status" -eq 0 ]]

  # Verify Node 1 connects to Node 2
  echo "[$(date +%T)] Waiting for connection"
  run mesh_wait_for_peer_connection 1 "${node2_peer_id}" 20
  if [[ "$status" -ne 0 ]]; then
    echo "Node 1 logs:"
    docker logs "${node1_name}"
    echo "Node 2 logs:"
    docker logs "${node2_name}"
  fi
  [[ "$status" -eq 0 ]]

  # Publish ban event for Node 2
  echo "[$(date +%T)] Publishing ban event"
  run docker exec "${hub_name}" /sam-hub admin ban --peer "${node2_peer_id}" --connect "/dns4/sam-hub/tcp/4002/p2p/${hub_peer_id}" --admin-token "e2e-token"
  
  echo "admin ban output: $output"
  [[ "$status" -eq 0 ]]
  if [[ "$output" != *"Published BANNED event"* ]]; then
    echo "Hub logs:"
    docker logs "${hub_name}"
  fi
  [[ "$output" == *"Published BANNED event"* ]]

  # Verify Node 1 receives the ban event and logs it
  run mesh_wait_for_log "${node1_name}" "Peer banned: ${node2_peer_id}" 20
  if [[ "$status" -ne 0 ]]; then
    echo "Node 1 logs:"
    docker logs "${node1_name}"
  fi
  [[ "$status" -eq 0 ]]

  # Verify Node 1 disconnects from Node 2
  echo "[$(date +%T)] Waiting for disconnection"
  run mesh_wait_for_peer_disconnection 1 "${node2_peer_id}" 20
  [[ "$status" -eq 0 ]]

  # Verify Node 1 cannot reconnect to Node 2
  echo "[$(date +%T)] Attempting to reconnect (should fail)"
  local node2_addr="/dns4/sam-node-2/tcp/5002/p2p/${node2_peer_id}"
  run docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://sam-node-1:8080/mcp/events" -tool "connect_peer" -args "{\"peer_addr\":\"${node2_addr}\"}"
  echo "Reconnect output: $output"
  [[ "$output" == *"gater disallows connection"* ]]
}
