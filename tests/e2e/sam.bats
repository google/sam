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

  # Start mock hub config server
  python3 -c '
import http.server
import socketserver
import sys

PORT = 8080

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/v1/config":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b"{\"public_key_hex\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"mesh_id\":\"test-mesh\",\"bootstrap_nodes\":[\"/ip4/127.0.0.1/tcp/4002/p2p/QmYyQSo1sn1GjUuQwca9AdvV8Zeyvmxrww8dDnewPrfJs9\"]}")
        else:
            self.send_response(404)
            self.end_headers()

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()
' &
  MOCK_HUB_PID=$!
  export MOCK_HUB_PID
  sleep 0.5
}

teardown() {
  kill "$MOCK_HUB_PID" || true
  wait "$MOCK_HUB_PID" 2>/dev/null || true
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
