#!/bin/bash

set -eu

function setup_suite {
  export PATH="${HOME}/go/bin:$PATH"
  export BATS_TEST_TIMEOUT=150

  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "docker not available or daemon not running" >&2
    exit 1
  fi
  if ! command -v kind >/dev/null 2>&1; then
    echo "kind not available" >&2
    exit 1
  fi
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl not available" >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq not available" >&2
    exit 1
  fi

  # tests/e2e
  cd "$BATS_TEST_DIRNAME"/../..
  make
  make docker-build

  if [[ ! -x "./bin/sam-node" || ! -x "./bin/sam-hub" || ! -x "./bin/mcp-client" ]]; then
    echo "missing binaries; run: make build" >&2
    exit 1
  fi

  export BATS_TEST_NUMBER=0
  source tests/e2e/lib/container_mesh.bash
  mesh_setup_env
  export MESH_PREFIX
  export MESH_NETWORK
  
  # Ensure the mock oidc and hub are running for all tests
  mesh_start_mock_oidc
  mesh_start_hub
}

function teardown_suite {
  cd "$BATS_TEST_DIRNAME"/../..
  source tests/e2e/lib/container_mesh.bash
  mesh_cleanup_suite
  echo "teardown suite"
}