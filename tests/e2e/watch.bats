#!/usr/bin/env bats

setup() {
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"


  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export HOME="$TEST_TMPDIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  mkdir -p "$XDG_CONFIG_HOME"

  # Generate mock DB
  go run tests/e2e/gen_db.go "$XDG_CONFIG_HOME/sam-mesh/agent.db"
}

teardown() {
  chmod -R +w "$TEST_TMPDIR" || true
  rm -rf "$TEST_TMPDIR"
}

@test "sam-node run --trust-hub-rbac with stored identity fails if hub is unreachable" {
  run "$SAM_NODE_BINARY" run --listen /ip4/127.0.0.1/udp/0/quic-v1 --listen /ip4/127.0.0.1/tcp/0
  
  if [[ "$status" -eq 0 ]]; then
    echo "Test failed: Node was expected to exit with non-zero status"
    echo "Output: $output"
    return 1
  fi

  if [[ ! "$output" == *"all connection attempts failed"* ]]; then
    echo "Test failed: Node did not log the expected error message"
    echo "Output: $output"
    return 1
  fi
}
