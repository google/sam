#!/usr/bin/env bats

setup() {
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"
  export SAM_HUB_BINARY="${SAM_HUB_BINARY:-./bin/sam-hub}"
  export MCP_CLIENT_BINARY="${MCP_CLIENT_BINARY:-./bin/mcp-client}"

  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export HOME="$TEST_TMPDIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  mkdir -p "$XDG_CONFIG_HOME"


}

teardown() {

  rm -rf "$TEST_TMPDIR"
}

@test "sam-node --help returns success" {
  run "$SAM_NODE_BINARY" --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Sovereign Agent Mesh Node"* ]]
}



@test "sam-node run without identity starts unauthenticated sidecar and serves mcp" {
  # Start sam-node in background with a specific port to avoid conflicts
  "$SAM_NODE_BINARY" run --bind-addr "127.0.0.1:8085" > "$TEST_TMPDIR/unauth-node.log" 2>&1 &
  local node_pid=$!

  # Give it a moment to start
  sleep 2

  # Call get_login_instructions using mcp-client
  run "$MCP_CLIENT_BINARY" -url "http://127.0.0.1:8085/mcp" -tool "get_login_instructions" -args "{}"
  
  # Clean up
  kill "$node_pid" || true
  wait "$node_pid" || true

  # Check the output of mcp-client
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"The node is unauthenticated. Please open a regular terminal and run:"* ]]
  [[ "$output" == *"sam-node join"* ]]
  
  # Check node logs for the initial message
  local log_output
  log_output=$(cat "$TEST_TMPDIR/unauth-node.log")
  [[ "$log_output" == *"No identity found. Starting unauthenticated sidecar for enrollment over MCP"* ]]
}



@test "sam-hub --help returns success" {
  run "$SAM_HUB_BINARY" --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Sovereign Agent Mesh - Multi-Transport Hub"* ]]
}
