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

@test "sam up --help returns success" {
  run "$SAM_BINARY" up --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Run the SAM node"* ]] || [[ "$output" == *"run-for"* ]]
}

@test "sam publish --help returns success" {
  run "$SAM_BINARY" publish --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"--skill"* ]]
}

@test "sam identity --help lists subcommands" {
  run "$SAM_BINARY" identity --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"login"* ]] || [[ "$output" == *"whoami"* ]]
}

@test "sam call --help shows capability option" {
  run "$SAM_BINARY" call --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"--capability"* ]] || [[ "$output" == *"call"* ]]
}

@test "sam mesh get agents --help returns success" {
  run "$SAM_BINARY" mesh get agents --help
  [[ "$status" -eq 0 ]]
}

@test "sam inspect biscuit parses and explains a token" {
  token="alice;allow_skill=risk-audit,weather-bot"
  run "$SAM_BINARY" inspect biscuit "$token"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"alice"* ]]
  [[ "$output" == *"risk-audit"* ]]
  [[ "$output" == *"weather-bot"* ]]
}

@test "sam inspect biscuit outputs JSON when token has multiple skills" {
  token="bob;allow_skill=chat,email"
  run "$SAM_BINARY" inspect biscuit "$token"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"bob"* ]]
  [[ "$output" == *"chat"* ]]
  [[ "$output" == *"email"* ]]
}

@test "sam publish --dry-run=client outputs card structure" {
  run "$SAM_BINARY" publish --skill weather-bot --mcp-port 9999 --dry-run=client
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'"peer_id"'* ]]
  [[ "$output" == *'"weather-bot"'* ]]
}

@test "sam call --dry-run=client validates request without network" {
  run "$SAM_BINARY" call test-peer --message "hello" --dry-run=client
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'"target"'* ]] || [[ "$output" == *'"capability"'* ]]
}

@test "sam inspect card decodes JSON agent card" {
  card_json='{"peer_id":"test-peer","alg":"libp2p-ed25519","signature":"test","agent_card":{"name":"test"},"issued_at":"2026-01-01T00:00:00Z"}'
  run "$SAM_BINARY" inspect card "$card_json"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"test-peer"* ]] || [[ "$output" == *"Peer ID"* ]]
}

@test "sam proxy --help returns success" {
  run "$SAM_BINARY" proxy --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"X-SAM-Target"* ]] || [[ "$output" == *"--port"* ]]
}

@test "sam proxy rejects requests without local identity login" {
  proxy_port=18080
  proxy_log="$TEST_TMPDIR/proxy.log"

  "$SAM_BINARY" proxy --port "$proxy_port" --listen /ip4/127.0.0.1/udp/4212/quic-v1 --run-for 10s >"$proxy_log" 2>&1 &
  proxy_pid=$!

  status_code="000"
  for _ in {1..40}; do
    status_code="$(curl -s -o "$TEST_TMPDIR/proxy_body.txt" -w "%{http_code}" -H "X-SAM-Target: 12D3KooWJ5x6k6U4k6M8QfR5fE3iZ7W2V2QX2c9Lr4R8D8vH" "http://127.0.0.1:${proxy_port}/health" || true)"
    if [[ "$status_code" != "000" ]]; then
      break
    fi
    sleep 0.1
  done

  kill "$proxy_pid" >/dev/null 2>&1 || true
  wait "$proxy_pid" >/dev/null 2>&1 || true

  [[ "$status_code" == "401" ]]
  run cat "$TEST_TMPDIR/proxy_body.txt"
  [[ "$output" == *"unauthorized"* ]]
}

@test "sam proxy /.sam/search discovers writer skill" {
  node_a_log="$TEST_TMPDIR/node-a.log"
  node_b_log="$TEST_TMPDIR/node-b.log"
  proxy_port=18081
  node_a_listen="/ip4/127.0.0.1/udp/4313/quic-v1"
  node_b_listen="/ip4/127.0.0.1/udp/4314/quic-v1"

  "$SAM_BINARY" proxy --port "$proxy_port" --listen "$node_b_listen" --dht-mode server --run-for 20s >"$node_b_log" 2>&1 &
  node_b_pid=$!

  node_b_peer=""
  for _ in {1..100}; do
    node_b_peer="$(grep -o 'peer_id=[^ ]*' "$node_b_log" | head -n1 | cut -d= -f2)"
    if [[ -n "$node_b_peer" ]]; then
      break
    fi
    sleep 0.1
  done
  [[ -n "$node_b_peer" ]]

  node_a_peer=""
  "$SAM_BINARY" publish --skill writer --mcp-port 19099 --listen "$node_a_listen" --bootstrap "/ip4/127.0.0.1/udp/4314/quic-v1/p2p/${node_b_peer}" --dht-mode server --run-for 20s >"$node_a_log" 2>&1 &
  node_a_pid=$!

  for _ in {1..120}; do
    node_a_peer="$(grep -o 'peer_id=[^ ]*' "$node_a_log" | head -n1 | cut -d= -f2)"
    if [[ -n "$node_a_peer" ]]; then
      break
    fi
    sleep 0.1
  done
  [[ -n "$node_a_peer" ]]

  search_status="000"
  for _ in {1..120}; do
    search_status="$(curl -s -o "$TEST_TMPDIR/search_body.json" -w "%{http_code}" "http://127.0.0.1:${proxy_port}/.sam/search?skill=writer" || true)"
    if [[ "$search_status" == "200" ]] && grep -q "$node_a_peer" "$TEST_TMPDIR/search_body.json"; then
      break
    fi
    sleep 0.2
  done

  kill "$node_b_pid" >/dev/null 2>&1 || true
  wait "$node_b_pid" >/dev/null 2>&1 || true
  kill "$node_a_pid" >/dev/null 2>&1 || true
  wait "$node_a_pid" >/dev/null 2>&1 || true

  [[ "$search_status" == "200" ]]
  run cat "$TEST_TMPDIR/search_body.json"
  [[ "$output" == *"$node_a_peer"* ]]
  [[ "$output" == *'"signature"'* ]]
}
