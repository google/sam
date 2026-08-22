#!/usr/bin/env bats

# The sandbox boundary, as an agent actually meets it: a container with no
# network at all, holding nothing but a socket, reaching the mesh through it.
#
# Everything here runs with --network none. That is the assertion as much as the
# arrangement: if any of it worked because a container could route somewhere,
# the test would be measuring the wrong thing.

load "lib/container_mesh.bash"

setup() {
  mesh_setup_env
}

teardown() {
  docker rm -f "${MESH_PREFIX}-box" "${MESH_PREFIX}-agent" >/dev/null 2>&1 || true
  mesh_cleanup_test_resources
}

# agent_curl runs a command inside the agent sandbox. It is an ordinary curl
# with no proxy flag: the sandbox has one route and it leads to the boundary, so
# reaching the mesh takes no cooperation from the client.
agent_curl() {
  docker exec "${MESH_PREFIX}-agent" curl -s -o /dev/null -w '%{http_code}' \
    --max-time 10 "$@"
}

@test "an agent with no network reaches the mesh through its socket, and nothing else" {
  run mesh_start_mock_oidc
  [[ "$status" -eq 0 ]]
  mesh_start_router

  # The node keeps its API on a socket in a directory the gateway shares. Run it
  # as the invoking user so the socket it creates is usable from the host side,
  # which also means naming a data directory: with a uid the image does not know,
  # HOME is unwritable and the default location cannot be created.
  mesh_start_node 1 "--socket-path /sockets/node.sock --data-dir /sockets/node-data" "" \
    "-v ${MESH_SOCKET_DIR}:/sockets --user $(id -u):$(id -g) -e HOME=/sockets"
  mesh_wait_for_log "${MESH_PREFIX}-node-1" "SAM Node Online" 60
  mesh_wait_for_mcp_ready 1 20

  # The gateway consumes the node. It has no network either: the node's socket
  # is the only thing it needs.
  docker run -d --name "${MESH_PREFIX}-box" \
    --network none \
    --user "$(id -u):$(id -g)" \
    -v "${MESH_SOCKET_DIR}:/sockets" \
    "${MESH_RUNTIME_IMAGE}" \
    /usr/local/bin/sam-box run \
      --socket /sockets/agent.sock \
      --sidecar-socket /sockets/node.sock \
      --egress-allow example.invalid \
      --log-level debug >/dev/null

  local waited=0
  while [[ ! -S "${MESH_SOCKET_DIR}/agent.sock" ]] && [[ "${waited}" -lt 100 ]]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  [[ -S "${MESH_SOCKET_DIR}/agent.sock" ]] || {
    docker logs "${MESH_PREFIX}-box"
    false
  }

  # The sandbox: no network, no credential, no proxy configuration. nano-init is
  # PID 1 and builds the only route out, so the client above is unmodified and
  # does not know it is confined. NET_ADMIN and /dev/net/tun are what building
  # that route costs.
  docker run -d --name "${MESH_PREFIX}-agent" \
    --network none \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    --user 0:0 \
    -v "${MESH_SOCKET_DIR}:/sockets" \
    --entrypoint /usr/local/bin/nano-init \
    "${MESH_RUNTIME_IMAGE}" \
    run /sockets/agent.sock sleep 300 >/dev/null

  # Wait for the route rather than sleeping: a request issued before tun0 is up
  # fails for a reason that has nothing to do with the mesh.
  local waited=0
  until docker exec "${MESH_PREFIX}-agent" ip route show default 2>/dev/null | grep -q tun0; do
    sleep 0.2
    waited=$((waited + 1))
    [[ "${waited}" -lt 50 ]] || {
      docker logs "${MESH_PREFIX}-agent"
      false
    }
  done

  # What an agent is for: the mesh's inference and tool endpoints, by name.
  run agent_curl "http://mesh.sam.alt/v1/models"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "200" ]] || {
    echo "GET /v1/models returned ${output}"
    docker logs "${MESH_PREFIX}-box"
    false
  }

  run agent_curl -X POST "http://mesh.sam.alt/mcp"
  [[ "$status" -eq 0 ]]
  # The MCP endpoint answers; which status it picks for a bare POST is the SDK's
  # business, but it must not be the gateway's 403.
  [[ "$output" != "403" ]]

  # The node's own API is not the agent's to reach. Registering would let it
  # advertise itself into the mesh under the node's identity.
  local forbidden
  for forbidden in /sam/service/register /sam/service/discover /metrics /healthz /; do
    run agent_curl "http://mesh.sam.alt${forbidden}"
    [[ "$status" -eq 0 ]]
    [[ "$output" == "403" ]] || {
      echo "GET ${forbidden} returned ${output}, want 403"
      false
    }
  done

  # Egress is deny-by-default, and a name nobody allowed is refused by the
  # boundary rather than dialled.
  run docker exec "${MESH_PREFIX}-agent" curl -s --max-time 10 "http://blocked.invalid/"
  [[ "$status" -ne 0 ]]
}
