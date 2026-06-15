#!/usr/bin/env bats

setup() {
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"
  export SAM_HUB_BINARY="${SAM_HUB_BINARY:-./bin/sam-hub}"
  if [[ ! -x "$SAM_NODE_BINARY" ]]; then
    skip "sam-node binary not found at $SAM_NODE_BINARY"
  fi

  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export HOME="$TEST_TMPDIR/home"
  export SAM_DATA_DIR="$TEST_TMPDIR/data"
  mkdir -p "$SAM_DATA_DIR"
}

teardown() {
  chmod -R +w "$TEST_TMPDIR" || true
  rm -rf "$TEST_TMPDIR"
}

@test "sam-node run with stored identity fails if hub is unreachable" {
  DB_PATH="$SAM_DATA_DIR/agent.db"
  go run tests/e2e/gen_db.go "$DB_PATH"

  log_file="$TEST_TMPDIR/run.log"
  run "$SAM_NODE_BINARY" run --listen /ip4/127.0.0.1/udp/0/quic-v1 --listen /ip4/127.0.0.1/tcp/0 --api-token "dummy-token" --bind-addr "127.0.0.1:0" >"$log_file" 2>&1
  
  if [[ "$status" -eq 0 ]]; then
    echo "Test failed: Node was expected to exit with non-zero status"
    cat "$log_file"
    return 1
  fi

  if ! grep -q "failed to authenticate with any hub: all connection attempts failed" "$log_file"; then
    echo "Test failed: Node did not log the expected error message"
    cat "$log_file"
    return 1
  fi
}

@test "sam-node run with stored identity reaches online state when hub is reachable" {
  if [[ ! -x "$SAM_HUB_BINARY" ]]; then
    skip "sam-hub binary not found at $SAM_HUB_BINARY"
  fi

  hub_log="$TEST_TMPDIR/hub.log"
  "$SAM_HUB_BINARY" start >"$hub_log" 2>&1 &
  hub_pid=$!

  # Wait for hub to start
  sleep 2

  # Join node to the hub to get a valid stored identity
  join_log="$TEST_TMPDIR/join.log"
  "$SAM_NODE_BINARY" join "http://127.0.0.1:9090" >"$join_log" 2>&1

  log_file="$TEST_TMPDIR/run.log"
  "$SAM_NODE_BINARY" run --listen /ip4/127.0.0.1/udp/0/quic-v1 --listen /ip4/127.0.0.1/tcp/0 --api-token "dummy-token" --bind-addr "127.0.0.1:0" >"$log_file" 2>&1 &
  node_pid=$!

  online=""
  for _ in {1..40}; do
    if grep -q "SAM Node Online" "$log_file"; then
      online="yes"
      break
    fi
    sleep 0.1
  done

  kill "$node_pid" >/dev/null 2>&1 || true
  wait "$node_pid" >/dev/null 2>&1 || true
  kill "$hub_pid" >/dev/null 2>&1 || true
  wait "$hub_pid" >/dev/null 2>&1 || true

  if [[ "$online" != "yes" ]]; then
    echo "Test failed. Node logs:"
    cat "$log_file"
  fi

  [[ "$online" == "yes" ]]
}
