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

set -euo pipefail

# If running locally, we might want to store logs in a temp dir
LOG_DIR="${RUNNER_TEMP:-$(mktemp -d)}"

echo "== Enrolling a local sam-node =="
./development/kind/run-local-node.sh > "$LOG_DIR/local-node.log" 2>&1 &
PID=$!
for _ in $(seq 1 60); do
  grep -q "SAM Node Online" "$LOG_DIR/local-node.log" && break
  kill -0 "$PID" 2>/dev/null || { echo "local node exited early:"; cat "$LOG_DIR/local-node.log"; exit 1; }
  sleep 1
done
grep -q "SAM Node Online" "$LOG_DIR/local-node.log" \
  || { echo "local node did not come online:"; cat "$LOG_DIR/local-node.log"; exit 1; }
echo "local node online"

# Make sure we clean up the local node when the script exits
trap 'kill $PID 2>/dev/null || true' EXIT

URL=http://127.0.0.1:9099/mcp
mcp() { ./bin/mcp-client -url "$URL" -token "devtoken" -timeout 20 "$@" 2>/dev/null; }

echo "== get_mesh_info =="
info=$(mcp -tool get_mesh_info -args '{}')
echo "$info"
echo "$info" | jq -e '.hub_peer_id != "" and (.dht_size > 0)' >/dev/null \
  || { echo "get_mesh_info assertion failed"; exit 1; }

echo "== discover services / find calculator (poll) =="
peer=""
for i in $(seq 1 90); do
  tools="$(mcp -tool find_remote_tools -args '{}' 2>/dev/null || true)"
  echo "discover attempt $i: $tools"

  peer="$(printf '%s' "$tools" \
    | jq -r '.[]? | select(.tool_name=="mcp://calculator/add") | .peer_id' 2>/dev/null \
    | head -n1 || true)"

  if [ -n "$peer" ]; then
    echo "mcp://calculator/add discovered on peer: $peer (attempt $i)"
    break
  fi

  # periodic mesh debug
  if [ $((i % 10)) -eq 0 ]; then
    echo "mesh info (attempt $i):"
    mcp -tool get_mesh_info -args '{}' || true
  fi

  sleep 1
done

[ -n "$peer" ] || {
  echo "mcp://calculator/add not discovered after 90s"
  echo "final find_remote_tools:"
  mcp -tool find_remote_tools -args '{}' || true
  echo "final mesh info:"
  mcp -tool get_mesh_info -args '{}' || true
  exit 1
}

echo "== call mcp://calculator/add(2,3) =="
result=$(mcp -tool call_remote_tool \
  -args "{\"peer_id\":\"$peer\",\"tool_name\":\"mcp://calculator/add\",\"arguments\":{\"a\":2,\"b\":3}}")
echo "result: $result"
if [[ "$result" != *"5"* ]]; then
  echo "calculator/add did not return 5"
  exit 1
fi
echo "OK: calculator/add(2,3) == 5"
