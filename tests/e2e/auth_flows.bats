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

@test "Authentication Flow 1: Client Credentials Flow" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  # mesh_start_node uses --token-url by default, which implements Client Credentials flow
  run mesh_start_node 1
  [[ "$status" -eq 0 ]]

  run mesh_assert_container_running "${MESH_PREFIX}-node-1"
  [[ "$status" -eq 0 ]]
}

@test "Authentication Flow 2: Device Authorization Flow (Interactive)" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  # 1. Get a token from mock provider using Python helper
  local token
  token=$(docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "import urllib.request; import json; req = urllib.request.Request('http://mock-oidc:18080/token', data=b''); resp = urllib.request.urlopen(req); print(json.loads(resp.read().decode())['access_token'])")
  
  [[ -n "${token}" ]]

  # 2. Run sam-node join to enroll and store identity
  local node_name="${MESH_PREFIX}-node-login"
  local hub_peer_id
  hub_peer_id=$(cat "/tmp/${MESH_PREFIX}-hub-peer-id")

  local data_vol="${MESH_PREFIX}-data"
  docker volume create "${data_vol}"
  
  docker run --rm \
    --network "${MESH_NETWORK}" \
    -v "${data_vol}:/root/.config/sam-mesh" \
    "sam-node:local" \
    join "http://sam-hub:9090"
    
  # Now run the node with the stored identity
  docker run -d \
    --name "${node_name}" \
    --network "${MESH_NETWORK}" \
    -v "${data_vol}:/root/.config/sam-mesh" \
    "sam-node:local" \
    run \
    --hub "http://sam-hub:9090"

  mesh_wait_for_log "${node_name}" "Using stored identity." 20
  
  # Cleanup volume
  docker volume rm "${data_vol}" >/dev/null 2>&1 || true
}

@test "Authentication Flow 3: Workload Identity Federation (JWT Path)" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  # 1. Get a token from mock provider
  local token
  token=$(docker run --rm --network "${MESH_NETWORK}" python:3.12 python3 -c "import urllib.request; import json; req = urllib.request.Request('http://mock-oidc:18080/token', data=b''); resp = urllib.request.urlopen(req); print(json.loads(resp.read().decode())['access_token'])")

  [[ -n "${token}" ]]

  # 2. Save it to a file in a volume
  local token_vol="${MESH_PREFIX}-token"
  docker volume create "${token_vol}"
  
  docker run --rm \
    -v "${token_vol}:/tokens" \
    busybox \
    sh -c "echo \"${token}\" > /tokens/sa-token"

  # 3. Run sam-node with --jwt-path
  local node_name="${MESH_PREFIX}-node-wi"
  local hub_peer_id
  hub_peer_id=$(cat "/tmp/${MESH_PREFIX}-hub-peer-id")

  docker run -d \
    --name "${node_name}" \
    --network "${MESH_NETWORK}" \
    -v "${token_vol}:/var/run/secrets/tokens" \
    "sam-node:local" \
    run \
    --hub "http://sam-hub:9090" \
    --jwt-path "/var/run/secrets/tokens/sa-token" \
    --api-token "secret-token"

  mesh_wait_for_log "${node_name}" "SAM Node Online" 20
  
  # Cleanup volume
  docker volume rm "${token_vol}" >/dev/null 2>&1 || true
}
