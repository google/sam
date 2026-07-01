#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
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
  mesh_start_node 1

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
  token=$(docker run --rm --network "${MESH_NETWORK}" $(mesh_get_add_hosts) python:3.12 python3 -c "import urllib.request; import json; req = urllib.request.Request('http://mock-oidc:18080/token', data=b''); resp = urllib.request.urlopen(req); print(json.loads(resp.read().decode())['access_token'])")
  
  [[ -n "${token}" ]]

  # 2. Run sam-node join to enroll and store identity
  local node_name="${MESH_PREFIX}-node-login"
  local hub_peer_id
  hub_peer_id=$(cat "/tmp/${MESH_PREFIX}-hub-peer-id")

  local data_vol="${MESH_PREFIX}-data"
  docker volume create "${data_vol}"
  CLEANUP_VOLUMES+=("${data_vol}")
  
  docker run --name "${node_name}-join" \
    --network "${MESH_NETWORK}" \
    $(mesh_get_add_hosts) \
    -v "${data_vol}:/root/.config/sam-mesh" \
    "sam-node:local" \
    join "http://sam-hub:9090" > "/tmp/${node_name}-join.out" 2>&1 &
  local join_pid=$!
  MESH_CONTAINERS+=("${node_name}-join")

  # Wait for redirect_uri and state in the output
  local redirect_uri=""
  local state=""
  local port=""
  for i in {1..20}; do
    if grep -q "redirect_uri=" "/tmp/${node_name}-join.out"; then
      # Output format: http://mock-oidc...redirect_uri=http%3A%2F%2F127.0.0.1%3A<PORT>%2Fcallback&...&state=<STATE>
      local line
      line=$(grep "redirect_uri=" "/tmp/${node_name}-join.out" | head -n 1)
      redirect_uri=$(echo "$line" | grep -o 'redirect_uri=[^&]*' | cut -d= -f2 | tr -d '\r\n')
      state=$(echo "$line" | grep -o 'state=[^&]*' | cut -d= -f2 | tr -d '\r\n')
      
      # URL decode redirect_uri
      # e.g. http%3A%2F%2F127.0.0.1%3A41353%2Fcallback -> http://127.0.0.1:41353/callback
      redirect_uri=$(echo "$redirect_uri" | sed -e 's/%3A/:/g' -e 's/%2F/\//g')
      
      port=$(echo "$redirect_uri" | grep -o ':[0-9]*' | tr -d ':\r\n')
      if [[ -n "$port" && -n "$state" ]]; then
        break
      fi
    fi
    sleep 1
  done

  [[ -n "$port" ]] && [[ -n "$state" ]]

  # Trigger the callback in the sam-node container's network namespace
  docker run --rm --network "container:${node_name}-join" python:3.12 python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${port}/callback?code=dev_code_123&state=${state}')"

  # Wait for the join process to finish
  wait $join_pid
  docker rm -f "${node_name}-join" >/dev/null 2>&1 || true
    
  # Now run the node with the stored identity
  docker run -d \
    --name "${node_name}" \
    --network "${MESH_NETWORK}" \
    $(mesh_get_add_hosts) \
    -v "${data_vol}:/root/.config/sam-mesh" \
    "sam-node:local" \
    run \
    --hub "http://sam-hub:9090"
  MESH_CONTAINERS+=("${node_name}")

  mesh_wait_for_log "${node_name}" "Using stored identity." 20
}

@test "Authentication Flow 3: Workload Identity Federation (JWT Path)" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  # 1. Get a token from mock provider
  local token
  token=$(docker run --rm --network "${MESH_NETWORK}" $(mesh_get_add_hosts) python:3.12 python3 -c "import urllib.request; import json; req = urllib.request.Request('http://mock-oidc:18080/token', data=b''); resp = urllib.request.urlopen(req); print(json.loads(resp.read().decode())['access_token'])")

  [[ -n "${token}" ]]

  # 2. Save it to a file in a volume
  local token_vol="${MESH_PREFIX}-token"
  docker volume create "${token_vol}"
  CLEANUP_VOLUMES+=("${token_vol}")
  
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
    $(mesh_get_add_hosts) \
    -v "${token_vol}:/var/run/secrets/tokens" \
    "sam-node:local" \
    run \
    --hub "http://sam-hub:9090" \
    --jwt-path "/var/run/secrets/tokens/sa-token" \
    --api-token "secret-token"
  MESH_CONTAINERS+=("${node_name}")

  mesh_wait_for_log "${node_name}" "SAM Node Online" 20
}
