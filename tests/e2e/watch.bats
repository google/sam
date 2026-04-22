#!/usr/bin/env bats

setup() {
  export SAM_BINARY="${SAM_BINARY:-./bin/sam-agent}"
  if [[ ! -x "$SAM_BINARY" ]]; then
    skip "sam binary not found at $SAM_BINARY"
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

@test "sam mesh get agents --watch updates when a new agent is published" {
  watcher_log="$TEST_TMPDIR/mesh-watch.log"
  publisher_log="$TEST_TMPDIR/mesh-publisher.log"
  watcher_listen="/ip4/127.0.0.1/udp/4320/quic-v1"
  publisher_listen="/ip4/127.0.0.1/udp/4321/quic-v1"

  "$SAM_BINARY" mesh get agents --watch -o json --listen "$watcher_listen" --dht-mode server --run-for 20s >"$watcher_log" 2>&1 &
  watcher_pid=$!

  watcher_peer=""
  for _ in {1..100}; do
    watcher_peer="$(grep -o 'peer_id=[^ ]*' "$watcher_log" | head -n1 | cut -d= -f2)"
    if [[ -n "$watcher_peer" ]]; then
      break
    fi
    sleep 0.1
  done
  [[ -n "$watcher_peer" ]]

  "$SAM_BINARY" publish --skill writer --mcp-port 19100 --listen "$publisher_listen" --bootstrap "/ip4/127.0.0.1/udp/4320/quic-v1/p2p/${watcher_peer}" --dht-mode server --run-for 8s >"$publisher_log" 2>&1 &
  publisher_pid=$!

  publisher_peer=""
  for _ in {1..100}; do
    publisher_peer="$(grep -o 'peer_id=[^ ]*' "$publisher_log" | head -n1 | cut -d= -f2)"
    if [[ -n "$publisher_peer" ]]; then
      break
    fi
    sleep 0.1
  done
  [[ -n "$publisher_peer" ]]

  found=""
  for _ in {1..120}; do
    if grep -q "\"peer_id\":\"$publisher_peer\"" "$watcher_log" && grep -q 'writer' "$watcher_log"; then
      found="yes"
      break
    fi
    sleep 0.2
  done

  kill "$publisher_pid" >/dev/null 2>&1 || true
  wait "$publisher_pid" >/dev/null 2>&1 || true
  kill "$watcher_pid" >/dev/null 2>&1 || true
  wait "$watcher_pid" >/dev/null 2>&1 || true

  [[ "$found" == "yes" ]]
}