#!/usr/bin/env bats

setup() {
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"
  if [[ ! -x "$SAM_NODE_BINARY" ]]; then
    skip "sam-node binary not found at $SAM_NODE_BINARY"
  fi

  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export HOME="$TEST_TMPDIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  mkdir -p "$XDG_CONFIG_HOME"
}

teardown() {
  rm -rf "$TEST_TMPDIR"
}

@test "sam-node run with token reaches online state" {
  log_file="$TEST_TMPDIR/run.log"
  "$SAM_NODE_BINARY" run --token test-token --listen /ip4/127.0.0.1/udp/0/quic-v1 --listen /ip4/127.0.0.1/tcp/0 >"$log_file" 2>&1 &
  pid=$!

  online=""
  for _ in {1..40}; do
    if grep -q "SAM Node Online" "$log_file"; then
      online="yes"
      break
    fi
    sleep 0.1
  done

  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true

  [[ "$online" == "yes" ]]
}

@test "sam-node login enables run without --token" {
  run bash -c "printf 'persisted-token\n' | '$SAM_NODE_BINARY' login"
  [[ "$status" -eq 0 ]]

  log_file="$TEST_TMPDIR/run-stored.log"
  "$SAM_NODE_BINARY" run --listen /ip4/127.0.0.1/udp/0/quic-v1 --listen /ip4/127.0.0.1/tcp/0 >"$log_file" 2>&1 &
  pid=$!

  online=""
  for _ in {1..40}; do
    if grep -q "SAM Node Online" "$log_file"; then
      online="yes"
      break
    fi
    sleep 0.1
  done

  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true

  [[ "$online" == "yes" ]]
}
