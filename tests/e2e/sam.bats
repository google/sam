#!/usr/bin/env bats

setup() {
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"
  export SAM_HUB_BINARY="${SAM_HUB_BINARY:-./bin/sam-hub}"

  make 
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



@test "sam-node run without identity fails" {
  run "$SAM_NODE_BINARY" run
  [[ "$status" -ne 0 ]]
  [[ "$output" == *"No JWT or stored identity found"* ]]
}



@test "sam-hub --help returns success" {
  run "$SAM_HUB_BINARY" --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Sovereign Agent Mesh - Multi-Transport Hub"* ]]
}
