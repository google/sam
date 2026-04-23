#!/usr/bin/env bats

setup() {
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"
  export SAM_HUB_BINARY="${SAM_HUB_BINARY:-./bin/sam-hub}"

  if [[ ! -x "$SAM_NODE_BINARY" ]]; then
    skip "sam-node binary not found at $SAM_NODE_BINARY"
  fi
  if [[ ! -x "$SAM_HUB_BINARY" ]]; then
    skip "sam-hub binary not found at $SAM_HUB_BINARY"
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

@test "sam-node --help returns success" {
  run "$SAM_NODE_BINARY" --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Sovereign Agent Mesh Node"* ]]
}

@test "sam-node login --help returns success" {
  run "$SAM_NODE_BINARY" login --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Establish sovereign identity with the Hub"* ]]
}

@test "sam-node run without identity prints guidance" {
  run "$SAM_NODE_BINARY" run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"No identity found"* ]]
}

@test "sam-node login stores identity from stdin" {
  run bash -c "printf 'sample-token\n' | '$SAM_NODE_BINARY' login"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Success! Identity stored"* ]]
}

@test "sam-hub --help returns success" {
  run "$SAM_HUB_BINARY" --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Sovereign Agent Mesh - Multi-Transport Hub"* ]]
}
