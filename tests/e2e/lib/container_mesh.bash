#!/usr/bin/env bash

# Shared BATS helpers for containerized SAM mesh tests.

if [[ -z "${MESH_HELPERS_LOADED:-}" ]]; then
  MESH_HELPERS_LOADED=1

  MESH_RUNTIME_IMAGE="${MESH_RUNTIME_IMAGE:-sam-e2e-runtime:local}"
  MESH_NETWORK_SUBNET_BASE="${MESH_NETWORK_SUBNET_BASE:-172.31}"
  MESH_NETWORK=""
  MESH_CONTAINERS=()
  MESH_PREFIX=""
  MESH_SOCKET_DIR=""

  # Best-effort cleanup of leaked resources from prior failed runs.
  mesh_cleanup_stale_resources() {
    local ids
    ids="$(docker ps -aq --filter "name=mesh-")"
    if [[ -n "${ids}" ]]; then
      # shellcheck disable=SC2086
      docker rm -f ${ids} >/dev/null 2>&1 || true
    fi

    local nets
    nets="$(docker network ls --format '{{.Name}}' | grep '^mesh-.*-net$' || true)"
    if [[ -n "${nets}" ]]; then
      while IFS= read -r net; do
        [[ -z "${net}" ]] && continue
        docker network rm "${net}" >/dev/null 2>&1 || true
      done <<< "${nets}"
    fi
  }

  mesh_require_docker() {
    command -v docker >/dev/null 2>&1 || return 1
    docker info >/dev/null 2>&1 || return 1
    return 0
  }

  mesh_build_runtime_image() {
    docker build \
      -f tests/e2e/docker/Dockerfile.sam-runtime \
      -t "${MESH_RUNTIME_IMAGE}" \
      . >/dev/null
  }

  mesh_setup_env() {
    mesh_cleanup_stale_resources
    
    if ! docker image inspect "${MESH_RUNTIME_IMAGE}" >/dev/null 2>&1; then
      mesh_build_runtime_image
    fi

    MESH_PREFIX="mesh-${BATS_TEST_NUMBER}-$$-$(date +%s)"
    MESH_NETWORK="${MESH_PREFIX}-net"

    # Use a deterministic subnet slice to reduce chance of Docker IPAM exhaustion.
    local subnet
    local octet
    octet=$(( (BATS_TEST_NUMBER % 200) + 20 ))
    subnet="${MESH_NETWORK_SUBNET_BASE}.${octet}.0/24"

    if ! docker network create --subnet "${subnet}" "${MESH_NETWORK}" >/dev/null 2>&1; then
      docker network create "${MESH_NETWORK}" >/dev/null
    fi

    MESH_SOCKET_DIR="/tmp/${MESH_PREFIX}-sockets"
    mkdir -p "${MESH_SOCKET_DIR}"

    if ! docker image inspect sam-mock-oidc:local >/dev/null 2>&1; then
      docker build -t sam-mock-oidc:local -f tests/e2e/docker/Dockerfile.mock-oidc . >/dev/null
    fi
  }

  mesh_cleanup_env() {
    local c
    for c in "${MESH_CONTAINERS[@]}"; do
      docker rm -f "${c}" >/dev/null 2>&1 || true
    done
    if [[ -n "${MESH_NETWORK}" ]]; then
      docker network rm "${MESH_NETWORK}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${MESH_SOCKET_DIR}" ]]; then
      rm -rf "${MESH_SOCKET_DIR}"
    fi
    MESH_CONTAINERS=()
    MESH_NETWORK=""
  }

  mesh_gen_hex32() {
    hexdump -vn 32 -e '1/1 "%02x"' /dev/urandom
  }

  mesh_wait_for_log() {
    local container="$1"
    local needle="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s*10; i++)); do
      if docker logs "${container}" 2>&1 | grep -Fq "${needle}"; then
        return 0
      fi
      sleep 0.1
    done
    return 1
  }

  mesh_wait_for_mcp_ready() {
    local idx="$1"
    local timeout_s="${2:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      if docker run --rm --network "${MESH_NETWORK}" python:3.12 curl -s --max-time 5 -D - http://sam-node-${idx}:8080/mcp/events | grep -q "200 OK"; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_get_node_count_via_mcp() {
    local idx="$1"
    local output
    output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" -v "$(pwd)/bin/mcp-client:/mcp-client" python:3.12 /mcp-client -url "http://sam-node-${idx}:8080/mcp/events" 2>/dev/null)"
    echo "${output}" | jq '.known_peers | length'
  }

  mesh_wait_for_node_count() {
    local idx="$1"
    local expected="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      local output
      output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" -v "$(pwd)/bin/mcp-client:/mcp-client" python:3.12 /mcp-client -url "http://sam-node-${idx}:8080/mcp/events" 2>/dev/null)"
      echo "Node ${idx} get_mesh_info raw output: ${output}"
      local count
      count="$(echo "${output}" | jq '.known_peers | length')"
      echo "Node ${idx} reported known peers count: ${count}"
      if [[ "${count}" -eq "${expected}" ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_wait_for_peer_connection() {
    local idx="$1"
    local target_peer="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      local output
      output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" -v "$(pwd)/bin/mcp-client:/mcp-client" python:3.12 /mcp-client -url "http://sam-node-${idx}:8080/mcp/events" 2>/dev/null)"
      echo "[$(date +%T)] Node ${idx} get_mesh_info raw output: ${output}"
      local connected
      connected="$(echo "${output}" | jq -r --arg peer "$target_peer" '.connected_peers | index($peer) != null')"
      echo "[$(date +%T)] Node ${idx} connection to ${target_peer}: ${connected}"
      if [[ "${connected}" == "true" ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_wait_for_peer_disconnection() {
    local idx="$1"
    local target_peer="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      local output
      output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" -v "$(pwd)/bin/mcp-client:/mcp-client" python:3.12 /mcp-client -url "http://sam-node-${idx}:8080/mcp/events" 2>/dev/null)"
      echo "[$(date +%T)] Node ${idx} get_mesh_info raw output: ${output}"
      local connected
      connected="$(echo "${output}" | jq -r --arg peer "$target_peer" '.connected_peers | index($peer) != null')"
      echo "[$(date +%T)] Node ${idx} connection to ${target_peer}: ${connected}"
      if [[ "${connected}" == "false" ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_start_mock_oidc() {
    local name="${MESH_PREFIX}-oidc"
    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias mock-oidc \
      sam-mock-oidc:local >/dev/null

    MESH_CONTAINERS+=("${name}")
    mesh_wait_for_log "${name}" "Mock OIDC server ready" 30
  }

  mesh_start_hub() {
    local name="${MESH_PREFIX}-hub"
    local key
    key="$(mesh_gen_hex32)"

    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias sam-hub \
      "sam-hub:local" \
      --issuer "http://mock-oidc:18080" \
      --client-id "sam-e2e" \
      --allowed-audiences "sam-e2e,sam-mesh-audience" \
      --key "${key}" \
      --listen "/ip4/0.0.0.0/udp/4001/quic-v1" \
      --listen "/ip4/0.0.0.0/tcp/4002" \
      --mesh "e2e-mesh" >/dev/null

    MESH_CONTAINERS+=("${name}")
    mesh_wait_for_log "${name}" "PeerID:" 20
    
    # Extract Peer ID for nodes to use
    local peer_id
    peer_id=$(docker logs "${name}" 2>&1 | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)
    echo "${peer_id}" > "/tmp/${MESH_PREFIX}-hub-peer-id"
    echo "Extracted Hub PeerID: ${peer_id}"
  }

  mesh_start_node() {
    local idx="$1"
    local flags="${2:-}"
    local name="${MESH_PREFIX}-node-${idx}"

    local hub_peer_id
    hub_peer_id=$(cat "/tmp/${MESH_PREFIX}-hub-peer-id")

    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias "sam-node-${idx}" \
      "${MESH_RUNTIME_IMAGE}" \
      /usr/local/bin/sam-node run \
      ${flags} \
      --hub "/dns4/sam-hub/tcp/4002/p2p/${hub_peer_id}" \
      --client-id "sam-mesh-audience" \
      --client-secret "sam-e2e-secret" \
      --token-url "http://mock-oidc:18080/token" \
      --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
      --listen "/ip4/0.0.0.0/tcp/5002" \
      --bind-addr "0.0.0.0:8080" \
      --api-token "secret-token" \
      --mesh "e2e-mesh" >/dev/null

    MESH_CONTAINERS+=("${name}")
  }

  mesh_assert_container_running() {
    local name="$1"
    local state
    state="$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)"
    [[ "${state}" == "true" ]]
  }
fi
