#!/usr/bin/env bats

setup() {
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"
  if [[ ! -x "$SAM_NODE_BINARY" ]]; then
    skip "sam-node binary not found at $SAM_NODE_BINARY"
  fi

  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export HOME="$TEST_TMPDIR/home"

  # Match os.UserConfigDir per OS so gen_db.go and sam-node agree on the path.
  # On Linux, os.UserConfigDir honors $XDG_CONFIG_HOME before $HOME/.config, so
  # export it to keep both processes in sync even when the host has it set.
  case "$(uname)" in
    Darwin) DB_PATH="$HOME/Library/Application Support/sam-mesh/agent.db" ;;
    *)      export XDG_CONFIG_HOME="$HOME/.config"
            DB_PATH="$XDG_CONFIG_HOME/sam-mesh/agent.db" ;;
  esac
  mkdir -p "$(dirname "$DB_PATH")"

  # Generate mock DB
  go run tests/e2e/gen_db.go "$DB_PATH"
}

teardown() {
  chmod -R +w "$TEST_TMPDIR" || true
  rm -rf "$TEST_TMPDIR"
}

@test "sam-node run with stored identity reaches online state" {
  log_file="$TEST_TMPDIR/run.log"
  "$SAM_NODE_BINARY" run --listen /ip4/127.0.0.1/udp/0/quic-v1 --listen /ip4/127.0.0.1/tcp/0 --api-token "dummy-token" --bind-addr "127.0.0.1:0" >"$log_file" 2>&1 &
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

  if [[ "$online" != "yes" ]]; then
    echo "Test failed. Node logs:"
    cat "$log_file"
  fi

  [[ "$online" == "yes" ]]
}


