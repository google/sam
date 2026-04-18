#!/usr/bin/env bats

setup() {
  export SAM_BINARY="${SAM_BINARY:-./bin/sam}"
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

@test "sam mesh federations list shows federation management" {
  run "$SAM_BINARY" mesh federations list
  [[ "$status" -eq 0 ]]
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

@test "sam mesh federations drop --help mentions confirm flag" {
  run "$SAM_BINARY" mesh federations drop --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"confirm"* ]] || [[ "$output" == *"drop"* ]]
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
