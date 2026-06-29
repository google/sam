#!/usr/bin/env bats
#
# E2E for the service catalog. Topology (self-hosted catalog):
#   node-2  hosts the "calculator" MCP service (calc-mcp backend)
#   node-1  is the consumer AND hosts the catalog (sam-catalog registers to it)
#   sam-catalog  connects to node-1, ingests via discover + announce stream
#
# Covers: (1) services are retrieved via the catalog, (2) a service added on the
# fly is picked up by the catalog, (3) discovery falls back to the DHT when the
# catalog is gone. Requires docker (run with `make test-e2e` / `make e2e-test WHAT=catalog`).

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

# start_catalog runs sam-catalog pointed at node-1, reachable at sam-catalog:9090.
start_catalog() {
  local name="${MESH_PREFIX}-sam-catalog"
  docker run -d \
    --name "${name}" \
    --network "${MESH_NETWORK}" \
    --network-alias sam-catalog \
    "${MESH_RUNTIME_IMAGE}" \
    /usr/local/bin/sam-catalog \
    --node-url "http://sam-node-1:8080" \
    --node-token "secret-token" \
    --bind-addr "0.0.0.0:9090" \
    --own-url "http://sam-catalog:9090" \
    --rewalk-interval 5s \
    --sweep-interval 5s >/dev/null
  MESH_CONTAINERS+=("${name}")
  mesh_wait_for_log "${name}" "catalog MCP on" 20
}

# register_service <node_alias> <name> registers an MCP service on a node via the
# sidecar REST endpoint (Zero Trust: bearer token required).
register_service() {
  local node_alias="$1"
  local svc_name="$2"
  docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "
import json, urllib.request
data = {'service': {'type': 'SERVICE_TYPE_MCP', 'name': '${svc_name}', 'description': 'on-the-fly ${svc_name}'}, 'targetUrl': 'http://calc-mcp:7777/mcp'}
req = urllib.request.Request('http://${node_alias}:8080/sam/service/register', data=json.dumps(data).encode(), headers={'Authorization': 'Bearer secret-token', 'Content-Type': 'application/json'})
print(urllib.request.urlopen(req).read().decode())
"
}

# poll_catalog_has <name> <timeout_s>: query the catalog's own MCP until <name> is ingested.
poll_catalog_has() {
  local name="$1"
  local timeout_s="${2:-60}"
  local i out cnt
  for ((i=0; i<timeout_s; i++)); do
    out=$(docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client \
      -url "http://sam-catalog:9090/mcp" -tool "query_catalog" -args '{"type":"mcp"}' 2>/dev/null | tail -n 1)
    # catalog returns []catalog.Entry (Go default JSON field names: .Name).
    cnt=$(echo "$out" | jq --arg n "$name" '[.[] | select(.Name==$n)] | length' 2>/dev/null || echo 0)
    if [[ "${cnt:-0}" -ge 1 ]]; then return 0; fi
    sleep 1
  done
  return 1
}

# poll_discover_has <node_idx> <srv_name> <timeout_s>: call discover_remote_services
# on a node until it returns <srv_name>. Echoes the last discovery JSON on success.
poll_discover_has() {
  local idx="$1"
  local name="$2"
  local timeout_s="${3:-60}"
  local i out cnt
  for ((i=0; i<timeout_s; i++)); do
    out=$(docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client \
      -url "http://sam-node-${idx}:8080/mcp" -tool "discover_remote_services" -args '{"type":"mcp"}' 2>/dev/null | tail -n 1)
    # discover returns []DiscoveredProvider (snake_case JSON: .srv_name).
    cnt=$(echo "$out" | jq --arg n "$name" '[.[] | select(.srv_name==$n)] | length' 2>/dev/null || echo 0)
    if [[ "${cnt:-0}" -ge 1 ]]; then echo "$out"; return 0; fi
    sleep 1
  done
  return 1
}

setup() {
  export BATS_TEST_TIMEOUT=300
  mesh_setup_env
  build_calc_mcp_image
}

teardown() {
  mesh_cleanup_env
}

@test "catalog: services retrieved via catalog, added on the fly, with DHT fallback" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]
  mesh_start_hub

  # --- Provider node-2 hosting "calculator" ---
  echo "[$(date +%T)] Starting calc-mcp backend"
  start_calc_mcp

  echo "[$(date +%T)] Starting Node 2 with calculator service"
  run mesh_start_node 2 "--log-level debug" "tests/e2e/docker/calc-mcp/sam-node-config.yaml"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_log "${MESH_PREFIX}-node-2" "SAM Node Online" 60
  mesh_wait_for_mcp_ready 2 20

  local node2_peer_id
  node2_peer_id=$(docker logs "${MESH_PREFIX}-node-2" 2>&1 | grep "PeerID:" | head -n 1 | awk '{print $2}' | tr -d '\r')

  # --- Consumer node-1 (will also host the catalog) ---
  echo "[$(date +%T)] Starting Node 1"
  run mesh_start_node 1 "--log-level debug"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_log "${MESH_PREFIX}-node-1" "SAM Node Online" 60
  mesh_wait_for_mcp_ready 1 20

  echo "[$(date +%T)] Connecting Node 1 to Node 2"
  local node2_addr="/dns4/sam-node-2/tcp/5002/p2p/${node2_peer_id}"
  run docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client \
    -url "http://sam-node-1:8080/mcp" -tool "connect_peer" -args "{\"peer_addr\":\"${node2_addr}\"}"
  [[ "$status" -eq 0 ]]
  mesh_wait_for_peer_connection 1 "${node2_peer_id}" 20

  # --- Start the catalog (registers itself on node-1) ---
  echo "[$(date +%T)] Starting sam-catalog"
  start_catalog

  # ============ Phase 1: services retrieved via the catalog ============
  echo "[$(date +%T)] Phase 1: catalog ingests calculator, node-1 resolves via catalog"
  run poll_catalog_has "calculator" 60
  [[ "$status" -eq 0 ]]   # catalog ingested calculator (bootstrap + announce)

  run poll_discover_has 1 "calculator" 60
  echo "discover output: $output"
  [[ "$status" -eq 0 ]]   # node-1 discovery returns calculator
  echo "$output" | jq -e --arg pid "${node2_peer_id}" '[.[] | select(.srv_name=="calculator" and .peer_id==$pid)] | length >= 1' >/dev/null || return 1

  # Prove it came VIA the catalog (not the DHT fan-out). Explicit `|| return 1`
  # so this is a hard assertion regardless of the bats set-e behavior.
  docker logs "${MESH_PREFIX}-node-1" 2>&1 | grep -q "\[Catalog\] resolved" || return 1

  # ============ Phase 2: new service added on the fly ============
  echo "[$(date +%T)] Phase 2: register 'weather' on node-2, catalog picks it up live"
  run register_service "sam-node-2" "weather"
  [[ "$status" -eq 0 ]]

  run poll_catalog_has "weather" 60
  [[ "$status" -eq 0 ]]   # catalog ingested the new service dynamically (announce/re-walk)

  run poll_discover_has 1 "weather" 60
  echo "discover output: $output"
  [[ "$status" -eq 0 ]]   # node-1 now resolves the on-the-fly service via the catalog

  # ============ Phase 3: DHT fallback when the catalog is gone ============
  echo "[$(date +%T)] Phase 3: stop catalog, discovery must fall back to the DHT"
  docker rm -f "${MESH_PREFIX}-sam-catalog" >/dev/null 2>&1 || true

  # With the catalog process gone, the hosted-URL query fails -> fall back to DHT.
  run poll_discover_has 1 "calculator" 60
  echo "discover output (fallback): $output"
  [[ "$status" -eq 0 ]]   # discovery still works via the DHT path
}
