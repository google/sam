#!/usr/bin/env bats

load "lib/container_mesh.bash"

setup() {
  mesh_setup_env
}

teardown() {
  mesh_cleanup_env
}

@test "sam-console starts and proxies to control plane" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]

  run mesh_start_hub
  [[ "$status" -eq 0 ]]

  local console_name="${MESH_PREFIX}-console"
  
  # Admin token used by control plane test setup is "admin-secret-token"
  docker run -d \
    --name "${console_name}" \
    --network "${MESH_NETWORK}" \
    $(mesh_get_add_hosts) \
    "sam-console:local" \
    --hub "http://sam-control-plane:8080" \
    --bind-addr ":8081" \
    --admin-token "super-secret-admin-token"
    
  MESH_CONTAINERS+=("${console_name}")

  # Wait for console to be ready
  sleep 3

  # Test static index.html is served
  run docker run --rm --network "${MESH_NETWORK}" curlimages/curl -s "http://${console_name}:8081/"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"<title>SAM Console</title>"* ]]

  # Test proxy to control plane /admin/status (mapped under /api/)
  run docker run --rm --network "${MESH_NETWORK}" curlimages/curl -s -f -H "Authorization: Bearer super-secret-admin-token" "http://${console_name}:8081/api/admin/status"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"active_routers"* ]]
}
