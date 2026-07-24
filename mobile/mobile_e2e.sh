#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -xeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." &> /dev/null && pwd)
cd "$REPO_ROOT"

# Helper to kill background processes and docker containers on exit
cleanup() {
  echo "[E2E] Cleaning up background processes and containers..."
  echo "=== DOCKER LOGS: sam-control-plane ==="
  docker logs sam-control-plane 2>&1 || true
  echo "=== DOCKER LOGS: sam-router ==="
  docker logs sam-router 2>&1 || true
  echo "=== DOCKER LOGS: host-node ==="
  docker logs host-node 2>&1 || true
  echo "=== DOCKER LOGS: host-mock-mcp ==="
  docker logs host-mock-mcp 2>&1 || true
  echo "==============================="
  docker kill host-node sam-control-plane sam-router mock-oidc host-mock-mcp >/dev/null 2>&1 || true
  docker network rm sam-net >/dev/null 2>&1 || true
  rm -rf /tmp/host-node-data /tmp/control-plane-data /tmp/router-data
  adb reverse --remove-all || true
}
trap cleanup EXIT

# 1. Build host binaries and docker images
make build
make docker-build-control-plane docker-build-router docker-build-node docker-build-mock-oidc

# 2. Build Android x86_64 FFI library using the Makefile and copy to Flutter jniLibs
make mobile-ffi-android-x86_64
mkdir -p mobile/sam-node-app/android/app/src/main/jniLibs/x86_64
cp bin/android-x86_64/libsam.so mobile/sam-node-app/android/app/src/main/jniLibs/x86_64/libsam.so

# Create Docker bridge network
docker network create sam-net || true

# 3. Start the mock OIDC server container
docker run --name mock-oidc \
  --network sam-net \
  -p 18080:18080 \
  -d --rm \
  sam-mock-oidc:local

# Wait for OIDC server to be ready
timeout 15s bash -c 'until curl -s http://127.0.0.1:18080/ >/dev/null; do sleep 0.5; done'

# Set up adb reverse for OIDC
adb reverse tcp:18080 tcp:18080

# 4. Start the Control Plane and Router containers
rm -rf /tmp/control-plane-data /tmp/router-data
mkdir -p /tmp/control-plane-data /tmp/router-data

docker run --name sam-control-plane \
  --network sam-net \
  -p 37001:37001 \
  -v /tmp/control-plane-data:/data \
  -d --rm \
  sam-control-plane:local \
  --bind-address 0.0.0.0:37001 \
  --db-driver sqlite \
  --db-dsn /data/control-plane.db \
  --issuer http://mock-oidc:18080 \
  --allowed-audiences sam-mesh-audience,sam-hub-audience \
  --admin-token secret-admin-token \
  --insecure-skip-tls-verify \
  --log-level debug

ROUTER_JWT=$(curl -s -X POST -d "grant_type=client_credentials&client_id=router-client&client_secret=test-secret" http://127.0.0.1:18080/token | jq -r .access_token)

docker run --name sam-router \
  --network sam-net \
  -p 37002:37002 \
  -v /tmp/router-data:/data \
  -d --rm \
  sam-router:local \
  --control-plane http://sam-control-plane:37001 \
  --listen /ip4/0.0.0.0/tcp/37002 \
  --listen /ip4/0.0.0.0/udp/37002/quic-v1 \
  --external-addr /ip4/10.0.2.2/tcp/37002 \
  --external-addr /ip4/127.0.0.1/tcp/37002 \
  --external-addr /dns4/sam-router/tcp/37002 \
  --oidc-token "$ROUTER_JWT" \
  --keys-path /data/router.key \
  --allow-loopback \
  --log-level debug

# Set up adb reverse for Control Plane and Router
adb reverse tcp:37001 tcp:37001
adb reverse tcp:37002 tcp:37002

# Wait for Control Plane to be ready
timeout 15s bash -c 'until curl -s http://127.0.0.1:37001/info >/dev/null; do sleep 0.5; done'

# Seed initial mesh policy via REST API
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer secret-admin-token" \
  -d '{
    "roles": [
      {"name": "admin", "allowed_services": ["*"], "allowed_targets": ["*"]},
      {"name": "sam:role:router", "allowed_services": ["*"], "allowed_targets": ["*"]},
      {"name": "sam:role:node", "allowed_services": ["*"], "allowed_targets": ["*"]}
    ],
    "bindings": [
      {"role": "admin", "members": ["sam:system:authenticated"]},
      {"role": "sam:role:router", "members": ["group:routers"]}
    ]
  }' \
  http://127.0.0.1:37001/policies

# 5. Enroll and Start the External Node on Host inside Docker
rm -rf /tmp/host-node-data
mkdir -p /tmp/host-node-data

HOST_JWT=$(curl -s -X POST -d "grant_type=client_credentials&client_id=test-client&client_secret=test-secret" http://127.0.0.1:18080/token | jq -r .access_token)

docker run --name host-node \
  --network sam-net \
  -p 8081:8081 \
  -v /tmp/host-node-data:/data \
  --add-host=host.docker.internal:host-gateway \
  -d --rm \
  sam-node:local \
  run \
  --data-dir /data \
  --hub http://sam-control-plane:37001 \
  --jwt "$HOST_JWT" \
  --bind-addr 0.0.0.0:8081 \
  --api-token host-token \
  --allow-loopback \
  --enable-relay \
  --log-level debug

# Wait for external node to be ready
timeout 15s bash -c 'until curl -s -X POST -H "Authorization: Bearer host-token" -d "{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}" http://127.0.0.1:8081/mcp >/dev/null; do sleep 0.5; done'

# Start a local Mock MCP Server container on port 9091
docker run --name host-mock-mcp \
  --network sam-net \
  -p 9091:9091 \
  -d --rm \
  python:3.12 python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
class S(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        req = json.loads(post_data.decode("utf-8"))
        method = req.get("method")
        req_id = req.get("id")
        res_data = None
        if method == "initialize":
            res_data = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": {"name": "mock-mcp-server", "version": "1.0.0"}
                }
            }
        elif method == "tools/list":
            res_data = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "host-tool",
                            "description": "test tool on host",
                            "inputSchema": {"type": "object", "properties": {}}
                        }
                    ]
                }
            }
        elif method == "tools/call":
            params = req.get("params", {})
            if params.get("name") == "host-tool":
                res_data = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "Hello from Host!"}]
                    }
                }
        if res_data is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res_data).encode("utf-8"))
        else:
            self.send_response(202)
            self.end_headers()
HTTPServer(("0.0.0.0", 9091), S).serve_forever()
'

# Register a dummy MCP service on the host node pointing to the local mock server container (using container name)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer host-token" \
  -d '{"service":{"type":"SERVICE_TYPE_MCP","name":"host-tool","description":"test tool on host"},"targetUrl":"http://host-mock-mcp:9091"}' \
  http://127.0.0.1:8081/sam/service/register

# 7. Start the Android Emulator and run the Flutter integration test
# Since this script runs on CI inside ReactiveCircus/android-emulator-runner,
# the emulator is already started and adb is fully connected to the emulator.
cd mobile/sam-node-app

# Run Flutter integration test
flutter test integration_test/e2e_test.dart &
TEST_PID=$!

# 8. Monitor host node's MCP tool list to verify discovery of emulator-tool
echo "[E2E] Verifying host node can discover emulator-tool..."
DISCOVERED=0
for i in {1..300}; do
  if [ -f "$REPO_ROOT/bin/mcp-client" ]; then
    TOOLS=$("$REPO_ROOT/bin/mcp-client" -token host-token -url http://127.0.0.1:8081/mcp -tool find_remote_tools 2>/dev/null || true)
    if echo "$TOOLS" | grep -q "emulator-tool"; then
      echo "[E2E] Host successfully discovered emulator-tool!"
      DISCOVERED=1
      break
    fi
  fi
  sleep 1
done

# 9. Call emulator-tool from the host node to verify end-to-end communication
CALLED=0
if [ "$DISCOVERED" -eq 1 ]; then
  echo "[E2E] Calling emulator-tool from host node..."
  EMULATOR_PEER_ID=$(echo "$TOOLS" | jq -r '.[] | select(.tool_name | contains("emulator-tool")) | .peer_id' | head -n 1)
  EMULATOR_TOOL_NAME=$(echo "$TOOLS" | jq -r '.[] | select(.tool_name | contains("emulator-tool")) | .tool_name' | head -n 1)
  CALL_RESULT=$("$REPO_ROOT/bin/mcp-client" \
    -token host-token \
    -url http://127.0.0.1:8081/mcp \
    -tool call_remote_tool \
    -args "{\"peer_id\":\"$EMULATOR_PEER_ID\",\"tool_name\":\"$EMULATOR_TOOL_NAME\"}" 2>/dev/null || true)
  echo "[E2E] Call result: $CALL_RESULT"
  if echo "$CALL_RESULT" | grep -q "Hello from Android!"; then
    echo "[E2E] Host successfully executed emulator-tool!"
    CALLED=1
  else
    echo "[E2E] FAILED: Host failed to execute emulator-tool"
  fi
fi

# Wait for integration test execution to finalize
wait $TEST_PID
TEST_EXIT_STATUS=$?

if [ "$DISCOVERED" -ne 1 ]; then
  echo "[E2E] FAILED: Host failed to discover emulator-tool"
  exit 1
fi

if [ "$CALLED" -ne 1 ]; then
  echo "[E2E] FAILED: Host failed to execute emulator-tool"
  exit 1
fi

if [ "$TEST_EXIT_STATUS" -ne 0 ]; then
  echo "[E2E] FAILED: Emulator integration test failed with exit code $TEST_EXIT_STATUS"
  exit 1
fi

echo "[E2E] SUCCESS: Bidirectional mobile E2E test passed!"
exit 0
