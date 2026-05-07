#!/usr/bin/env bats

load "lib/container_mesh.bash"

# Custom mock OIDC server that returns 'data-scientist' role
mesh_start_mock_oidc_custom() {
  local name="${MESH_PREFIX}-oidc"
  local cmd
  read -r -d '' cmd <<'EOF' || true
python3 - <<'PY'
import json
import time
import jwt
from http.server import BaseHTTPRequestHandler, HTTPServer

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
                'roles': ['data-scientist'] # Custom role
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
      sam-mock-oidc:local \
      sh -c "${cmd}" >/dev/null

    MESH_CONTAINERS+=("${name}")
    mesh_wait_for_log "${name}" "Mock OIDC server ready" 30
}

mesh_call_remote_tool() {
  local caller_idx="$1"
  local target_peer_id="$2"
  local tool_name="$3"
  
  local args="{\"peer_id\":\"${target_peer_id}\",\"tool_name\":\"${tool_name}\",\"arguments\":\"{}\"}"
  
  docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://sam-node-${caller_idx}:8080/mcp/events" -tool "call_remote_tool" -args "${args}"
}

setup() {
  if ! mesh_require_docker; then
    skip "docker not available or daemon not running"
  fi

  if [[ ! -x "./bin/sam-node" || ! -x "./bin/sam-hub" ]]; then
    skip "missing binaries; run: make build"
  fi

  mesh_setup_env
  mkdir -p tests/e2e/logs

  # Create volume for policies
  export POLICY_VOL="${MESH_PREFIX}-policy"
  docker volume create "${POLICY_VOL}"

  # Write policies to volume
  local hub_policy="version: \"v1alpha1\"
roles:
  data-scientist:
    mcp:
      allowed_tools:
        - \"query_database\"
        - \"delete_tables\""

  local node_policy="version: \"v1alpha1\"
attenuation:
  policies:
    - 'deny if operation(\"delete_tables\");'"

  docker run --rm -v "${POLICY_VOL}:/policies" busybox sh -c "cat <<'EOF' > /policies/policies.yaml
${hub_policy}
EOF
cat <<'EOF' > /policies/local_policy.yaml
${node_policy}
EOF"

  # Start services
  run mesh_start_mock_oidc_custom
  [[ "$status" -eq 0 ]]

  # Start Hub with policy file
  local hub_name="${MESH_PREFIX}-hub"
  local key
  key="$(mesh_gen_hex32)"

  docker run -d \
    --name "${hub_name}" \
    --network "${MESH_NETWORK}" \
    --network-alias sam-hub \
    -v "${POLICY_VOL}:/etc/sam" \
    "sam-hub:local" \
    --issuer "http://mock-oidc:18080" \
    --client-id "sam-e2e" \
    --allowed-audiences "sam-e2e" \
    --key "${key}" \
    --listen "/ip4/0.0.0.0/udp/4001/quic-v1" \
    --listen "/ip4/0.0.0.0/tcp/4002" \
    --mesh "e2e-mesh" \
    --policy-file "/etc/sam/policies.yaml" >/dev/null

  MESH_CONTAINERS+=("${hub_name}")
  mesh_wait_for_log "${hub_name}" "PeerID:" 20
  
  local hub_peer_id
  hub_peer_id=$(docker logs "${hub_name}" 2>&1 | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)
  echo "${hub_peer_id}" > "/tmp/${MESH_PREFIX}-hub-peer-id"

  # Start Node 1 (Target) with local policy
  docker run -d \
    --name "${MESH_PREFIX}-node-1" \
    --network "${MESH_NETWORK}" \
    --network-alias "sam-node-1" \
    -v "${POLICY_VOL}:/etc/sam" \
    "sam-node:local" \
    run \
    --hub "http://sam-hub:9090" \
    --client-id "sam-e2e" \
    --client-secret "sam-e2e-secret" \
    --oidc-issuer "http://mock-oidc:18080" \
    --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
    --listen "/ip4/0.0.0.0/tcp/5002" \
    --bind-addr "0.0.0.0:8080" \
    --api-token "secret-token" \
    --mesh "e2e-mesh" \
    --config "/etc/sam/local_policy.yaml" >/dev/null

  MESH_CONTAINERS+=("${MESH_PREFIX}-node-1")
  mesh_wait_for_log "${MESH_PREFIX}-node-1" "Successfully enrolled" 20

  # Start Node 2 (Caller) without specific local policy
  mesh_start_node 2
  mesh_wait_for_mcp_ready 2

  mesh_wait_for_log "${MESH_PREFIX}-node-2" "SAM Node Online" 20
  local node2_id
  node2_id=$(docker logs "${MESH_PREFIX}-node-2" 2>&1 | grep -A 1 "SAM Node Online" | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)

  # Wait for discovery (Node 2 should see Node 1)
  local i
  local hub_id
  hub_id="$(cat "/tmp/${MESH_PREFIX}-hub-peer-id")"
  export TARGET_PEER_ID=""
  
  for ((i=0; i<40; i++)); do
    local output
    output="$(docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://sam-node-2:8080/mcp/events" -tool "get_mesh_info" 2>/dev/null)"
    TARGET_PEER_ID=$(echo "${output}" | grep -oE '12D3Koo[a-zA-Z0-9]+' | grep -v "${hub_id}" | grep -v "${node2_id}" | head -n 1)
    if [[ -n "${TARGET_PEER_ID}" ]]; then
      break
    fi
    sleep 1
  done

  echo "Node 2 logs after discovery loop:" >&3
  docker logs "${MESH_PREFIX}-node-2" >&3
  
  if [[ -z "${TARGET_PEER_ID}" ]]; then
    echo "Timeout waiting for discovery of Node 1"
    return 1
  fi

  # Explicitly connect Node 2 to Node 1 to avoid "no addresses" error
  local node1_addr="/dns4/sam-node-1/tcp/5002/p2p/${TARGET_PEER_ID}"
  docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://sam-node-2:8080/mcp/events" -tool "connect_peer" -args "{\"peer_addr\":\"${node1_addr}\"}" >/dev/null
}

teardown() {
  if [[ "${BATS_TEST_COMPLETED:-0}" -ne 1 ]]; then
    mkdir -p tests/e2e/logs
    local ids
    ids="$(docker ps -aq --filter "name=mesh-")"
    for id in ${ids}; do
      local name
      name="$(docker inspect -f '{{.Name}}' "${id}" | tr -d '/')"
      docker logs "${id}" > "tests/e2e/logs/${name}.log" 2>&1 || true
    done
  fi
  mesh_cleanup_env
  docker volume rm "${POLICY_VOL}" >/dev/null 2>&1 || true
}

@test "Policy E2E: Positive Path (Allowed by Hub, Not blocked by Node)" {
  run mesh_call_remote_tool 2 "${TARGET_PEER_ID}" "query_database"
  echo "Output: $output"
  [ "$status" -eq 0 ]
}

@test "Policy E2E: Negative Path (Denied by Hub)" {
  run mesh_call_remote_tool 2 "${TARGET_PEER_ID}" "reboot_server"
  echo "Output: $output"
  [[ "$output" == *"denied"* ]]
}

@test "Policy E2E: Attenuation Path (Allowed by Hub, Blocked by Node)" {
  run mesh_call_remote_tool 2 "${TARGET_PEER_ID}" "delete_tables"
  echo "Output: $output"
  [[ "$output" == *"denied"* ]]
}
