#!/usr/bin/env bash

# Shared BATS helpers for containerized SAM mesh tests.

if [[ -z "${MESH_HELPERS_LOADED:-}" ]]; then
  MESH_HELPERS_LOADED=1

  MESH_RUNTIME_IMAGE="${MESH_RUNTIME_IMAGE:-sam-e2e-runtime:local}"
  MESH_NETWORK=""
  MESH_CONTAINERS=()
  MESH_PREFIX=""

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
    MESH_PREFIX="mesh-${BATS_TEST_NUMBER}-$(date +%s)"
    MESH_NETWORK="${MESH_PREFIX}-net"
    docker network create "${MESH_NETWORK}" >/dev/null
  }

  mesh_cleanup_env() {
    local c
    for c in "${MESH_CONTAINERS[@]}"; do
      docker rm -f "${c}" >/dev/null 2>&1 || true
    done
    if [[ -n "${MESH_NETWORK}" ]]; then
      docker network rm "${MESH_NETWORK}" >/dev/null 2>&1 || true
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
      if docker logs "${container}" 2>&1 | grep -q "${needle}"; then
        return 0
      fi
      sleep 0.1
    done
    return 1
  }

  mesh_start_mock_oidc() {
    local name="${MESH_PREFIX}-oidc"
    local cmd
    read -r -d '' cmd <<'EOF' || true
python3 - <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/.well-known/openid-configuration':
            body = {
                'issuer': 'http://mock-oidc:18080',
                'authorization_endpoint': 'http://mock-oidc:18080/auth',
                'token_endpoint': 'http://mock-oidc:18080/token',
                'jwks_uri': 'http://mock-oidc:18080/keys'
            }
            data = json.dumps(body).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == '/keys':
            data = b'{"keys":[]}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

HTTPServer(('0.0.0.0', 18080), Handler).serve_forever()
PY
EOF

    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias mock-oidc \
      python:3.12-alpine \
      sh -lc "${cmd}" >/dev/null

    MESH_CONTAINERS+=("${name}")
    mesh_wait_for_log "${name}" "" 3 || true
  }

  mesh_start_hub() {
    local name="${MESH_PREFIX}-hub"
    local key
    key="$(mesh_gen_hex32)"

    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias sam-hub \
      "${MESH_RUNTIME_IMAGE}" \
      /usr/local/bin/sam-hub \
      --issuer "http://mock-oidc:18080" \
      --client-id "sam-e2e" \
      --client-secret "sam-e2e-secret" \
      --key "${key}" \
      --listen "/ip4/0.0.0.0/udp/4001/quic-v1" \
      --listen "/ip4/0.0.0.0/tcp/4002" \
      --mesh "e2e-mesh" \
      --public-url "http://sam-hub:8080" >/dev/null

    MESH_CONTAINERS+=("${name}")
    mesh_wait_for_log "${name}" "SAM Hub Online" 20
  }

  mesh_start_node() {
    local idx="$1"
    local name="${MESH_PREFIX}-node-${idx}"

    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias "sam-node-${idx}" \
      "${MESH_RUNTIME_IMAGE}" \
      /usr/local/bin/sam-node run \
      --hub "http://sam-hub:8080" \
      --token "token-${idx}" \
      --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
      --listen "/ip4/0.0.0.0/tcp/5002" >/dev/null

    MESH_CONTAINERS+=("${name}")
    mesh_wait_for_log "${name}" "SAM Node Online" 20
  }

  mesh_assert_container_running() {
    local name="$1"
    local state
    state="$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)"
    [[ "${state}" == "true" ]]
  }
fi
