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

# Helper to kill background processes on exit
NODE_PID=""
HUB_PID=""
OIDC_PID=""
cleanup() {
  echo "[E2E] Cleaning up background processes..."
  if [ -n "$NODE_PID" ]; then kill "$NODE_PID" || true; fi
  if [ -n "$HUB_PID" ]; then kill "$HUB_PID" || true; fi
  if [ -n "$OIDC_PID" ]; then kill "$OIDC_PID" || true; fi
  rm -rf /tmp/host-node-data
}
trap cleanup EXIT

# 1. Setup local DNS for mock-oidc
if ! grep -q "mock-oidc" /etc/hosts; then
  echo "127.0.0.1 mock-oidc" | sudo tee -a /etc/hosts
fi

# 2. Build host binaries
make build

# 3. Build FFI library for the Android Emulator architecture (x86_64)
mkdir -p mobile/sam-node-app/android/app/src/main/jniLibs/x86_64
GOOS=android GOARCH=amd64 CGO_ENABLED=1 go build -v -buildmode=c-shared -o mobile/sam-node-app/android/app/src/main/jniLibs/x86_64/libsam.so ./mobile/sam-node-ffi

# 4. Start the mock OIDC server
python3 tests/e2e/docker/mock_oidc.py &
OIDC_PID=$!

# Wait for OIDC server to be ready
timeout 15s bash -c 'until curl -s http://127.0.0.1:18080/ >/dev/null; do sleep 0.5; done'

# 5. Start the Hub
bin/sam-hub run \
  --bind-addr 127.0.0.1:37001 \
  --oidc-issuer http://mock-oidc:18080 \
  --mesh-id public-mesh \
  --insecure-skip-tls-verify &
HUB_PID=$!

# Wait for Hub to print PeerID
timeout 15s bash -c 'until bin/sam-hub --context local info 2>/dev/null; do sleep 0.5; done'

# 6. Enroll and Start the External Node on Host
rm -rf /tmp/host-node-data
HOST_JWT=$(curl -s -X POST -d "grant_type=client_credentials&client_id=test-client&client_secret=test-secret" http://127.0.0.1:18080/token | jq -r .access_token)

bin/sam-node enroll \
  --data-dir /tmp/host-node-data \
  --hub http://127.0.0.1:37001 \
  --jwt "$HOST_JWT" \
  --allow-loopback

bin/sam-node run \
  --data-dir /tmp/host-node-data \
  --hub http://127.0.0.1:37001 \
  --bind-addr 127.0.0.1:8081 \
  --api-token host-token \
  --allow-loopback &
NODE_PID=$!

# Wait for external node to be ready
timeout 15s bash -c 'until curl -s -X POST -H "Authorization: Bearer host-token" -d "{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}" http://127.0.0.1:8081/mcp >/dev/null; do sleep 0.5; done'

# Register a dummy MCP service on the host node
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer host-token" \
  -d '{"service":{"type":"SERVICE_TYPE_MCP","name":"host-tool","description":"test tool on host"},"targetUrl":"http://127.0.0.1:8081"}' \
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
for i in {1..45}; do
  if [ -f "$REPO_ROOT/bin/mcp-client" ]; then
    TOOLS=$("$REPO_ROOT/bin/mcp-client" -url http://127.0.0.1:8081/mcp -tool list_tools 2>/dev/null || true)
    if echo "$TOOLS" | grep -q "emulator-tool"; then
      echo "[E2E] Host successfully discovered emulator-tool!"
      DISCOVERED=1
      break
    fi
  fi
  sleep 1
done

# Wait for integration test execution to finalize
wait $TEST_PID

if [ "$DISCOVERED" -ne 1 ]; then
  echo "[E2E] FAILED: Host failed to discover emulator-tool"
  exit 1
fi

echo "[E2E] SUCCESS: Bidirectional mobile E2E test passed!"
exit 0
