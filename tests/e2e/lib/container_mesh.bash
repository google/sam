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
    local data='{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
    
    for ((i=0; i<timeout_s; i++)); do
      if docker run --rm -v "${MESH_SOCKET_DIR}:/sockets" -e SOCKET_PATH="/sockets/node-${idx}.sock" -e DATA="${data}" python:3.12 python3 -c "
import socket
import os
import sys

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.environ['SOCKET_PATH'])
    
    data = os.environ['DATA'].encode('utf-8')
    request = f\"POST /mcp HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Type: application/json\\r\\nAccept: application/json, text/event-stream\\r\\nContent-Length: {len(data)}\\r\\n\\r\\n\".encode('utf-8') + data
    
    s.sendall(request)
    response = s.recv(4096).decode('utf-8')
    s.close()
    
    if 'protocolVersion' in response:
        sys.exit(0)
except Exception as e:
    pass
sys.exit(1)
" >/dev/null 2>&1; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_get_node_count_via_mcp() {
    local idx="$1"
    local output
    output="$(docker run --rm -v "${MESH_SOCKET_DIR}:/sockets" -v "$(pwd)/bin/mcp-client:/mcp-client" python:3.12 /mcp-client -socket "/sockets/node-${idx}.sock" 2>/dev/null)"
    
    echo "${output}" | grep "Known peers count:" | awk '{print $4}' | tr -d '\r'
  }

  mesh_wait_for_node_count() {
    local idx="$1"
    local expected="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      local output
      output="$(docker run --rm -v "${MESH_SOCKET_DIR}:/sockets" -v "$(pwd)/bin/mcp-client:/mcp-client" python:3.12 /mcp-client -socket "/sockets/node-${idx}.sock" 2>/dev/null)"
      local count
      count="$(echo "${output}" | grep "Known peers count:" | awk '{print $4}' | tr -d '\r')"
      echo "Node ${idx} reported output: ${output}"
      if [[ "${count}" -eq "${expected}" ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_start_mock_oidc() {
    local name="${MESH_PREFIX}-oidc"
    local cmd
    read -r -d '' cmd <<'EOF' || true
python3 - <<'PY'
import json
import time
import jwt
from http.server import BaseHTTPRequestHandler, HTTPServer

# The following RSA private key and JWKS were generated for testing purposes.
# They are used by the mock OIDC server to sign JWTs.
# To generate a new key pair:
#   openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
#   openssl rsa -pubout -in private.pem -out public.pem
# Parameters: RSA 2048 bits, Algorithm: RS256, kid: test-key-id
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDGtPD85uaT342Y
yqGAiWQ6OV2BxvpXQRMzsb7VpdLa146xf5/1b9lIR4dFvhvGUqnyzFLV0EdIzTqo
xyKGHbQY68DIUjH3iwt6rzU0Vkw/3g/R/TBEmGwdqNDLCBItsLOnF4HfsxAWtjaU
R96S4oXaCUcXOD/3yHs0ha4tu8YgwGwMHa/CQRgcTX5FshR6uHow5G7NiOVYUcAP
c1HXmwmf0FeSY9r0QudmIjkJSeIH1I/BufpEqbcjrSyjYd4eldbhjlCvuIR93Sva
8jZBzdCW+xxyU+8dz2tEgRjm9G7CpoCpAwhcEQQW7XRUb8DP9+bid9VfT+3C1Te6
u8eowndXAgMBAAECggEAGF6ZjZKt5aXNolb7jp2K/r8JUkC6dBgFiFn8uwwOu4sj
M26hCgNRJRWsp+eEVYLO1/mqERHtpCaTUp61g7hB3aqQJqE6Ao95dW7megg5ar3L
t+ey0z7UR6DsFnJjdFoO9meiJHK7/uUS9YWI7P++BbsMjnL2GWfrgEoCzhYQ2vQ2
8t9lGmJfaEeicTcPs4/Jtz9nX+KQ1CqKb5uHP6IyVQjV/nIjWh1WZJV5wsmLM1ZF
YT7NPEhXkgH5JjwzEI3QR9ZMs4FUgbduImmS280YCMNMUNVsSBbbV/1hh7Sxlp6B
bRaK12sPPRwW0sHw3odZKjGzKIFlu9I5TieNJ5w2AQKBgQDy3cxDXxj+bcSYuWDp
p4EVNTwg+IY9eT0x1x+tWXaOjGTscD4GrdUYhspWuoUn5NxZ0ub0apiTMQfoM9a0
Qr3CKngkL5JTi6OwdnEaTPNvQiSJdgXXzYdCXeucK5soeHCZTPAb3bV27LtpxyMI
QSx9rnKcSyoRSavLWP0hr8QNVwKBgQDRc84q3I5tZX/whoUmeTj6aNJoIa1KAACM
0Fnr9ecjLS50kXIiTSCiNE8pcBcsSxYgo+PG5W9oQaZcdd7r2nJOqaizpjnHbF+9
S/Ts9vj+dJlCUcjjROghzYrI5mdb8Dq2Ngd93IcBt5H+W6bm8wWUgLy0IJmJDKHE
Z7SS22imAQKBgAETHi5GI3QsxCvw1g7yoM2ZOLTkpKNs/+pSi19XAAFNebzaGkwp
RMIhBpAvrxsoFhmHp2H5fsdX9jL+17pgeTp8uZ9fXoRkH8tOGt4E7SbW4haBoTD9
RdXzWHGOd9dMASOMhZt59a2bCpFDQlJtB2de+D7czkjZTJtPv38AqhttAoGAE8X2
Aa/etk8tu9xHN7GcAm/g5TnArUrAwops4szNLFH4n8KXXsufOBDuJEBTv7e6+Avg
1gcU9Ge2N+ZczDFMN0bnCUa5D62YgDtqfPB34zXIvi0QZPw9WeuYnYy610AfmtIQ
9P3btPrKipPGdukcbr+UkQC+3eRWZT9RGcgi4gECgYApA3J0jlD+JFtYKFOuJWxS
aFEhYPe2dVW78bJoMMhxPtD9hWw/zWVUdyhdXMHoP8/igwNiUqXaYacPbxTFu5ft
w/+UummqB6KpqPFnpbqP826Udr4SEHH0iwvs4MDqSlXcOC5CXbIoMLB/zMjE+u/J
IqNKTt9jbR4zISCpyOCsQw==
-----END PRIVATE KEY-----"""

JWKS = {
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "test-key-id",
      "n": "xrTw_Obmk9-NmMqhgIlkOjldgcb6V0ETM7G-1aXS2teOsX-f9W_ZSEeHRb4bxlKp8sxS1dBHSM06qMcihh20GOvAyFIx94sLeq81NFZMP94P0f0wRJhsHajQywgSLbCzpxeB37MQFrY2lEfekuKF2glHFzg_98h7NIWuLbvGIMBsDB2vwkEYHE1-RbIUerh6MORuzYjlWFHAD3NR15sJn9BXkmPa9ELnZiI5CUniB9SPwbn6RKm3I60so2HeHpXW4Y5Qr7iEfd0r2vI2Qc3QlvscclPvHc9rRIEY5vRuwqaAqQMIXBEEFu10VG_Az_fm4nfVX0_twtU3urvHqMJ3Vw",
      "e": "AQAB"
    }
  ]
}

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
            data = json.dumps(JWKS).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

    def do_POST(self):
        if self.path == '/token':
            payload = {
                'iss': 'http://mock-oidc:18080',
                'aud': 'sam-e2e',
                'sub': 'test-user',
                'exp': int(time.time()) + 3600,
                'roles': ['admin', 'user']
            }
            token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256', headers={'kid': 'test-key-id'})
            body = {
                'access_token': token,
                'token_type': 'Bearer',
                'expires_in': 3600
            }
            data = json.dumps(body).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.end_headers()

print("Mock OIDC server ready", flush=True)
HTTPServer(('0.0.0.0', 18080), Handler).serve_forever()
PY
EOF

    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias mock-oidc \
      python:3.12 \
      sh -lc "pip install pyjwt cryptography && ${cmd}" >/dev/null

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
      -v "${MESH_SOCKET_DIR}:/sockets" \
      "sam-node:local" \
      run \
      ${flags} \
      --hub "/dns4/sam-hub/tcp/4002/p2p/${hub_peer_id}" \
      --client-id "sam-e2e" \
      --client-secret "sam-e2e-secret" \
      --token-url "http://mock-oidc:18080/token" \
      --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
      --listen "/ip4/0.0.0.0/tcp/5002" \
      --mcp-socket "/sockets/node-${idx}.sock" \
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
