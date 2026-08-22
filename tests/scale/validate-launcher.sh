#!/usr/bin/env bash
#
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Run the fleet launcher for real, small.
#
# launch-microvms.sh is what a provisioned VM runs, and until this existed it
# had never been executed anywhere. A script that is only ever run for the first
# time on a fleet of cloud machines is a script whose bugs are discovered at the
# most expensive possible moment, so this runs it against a real mesh with a
# couple of sandboxes and checks the thing that matters: that the node ends up
# serving as many distinct agents as there are microVMs.
#
# Usage:
#   FC_KERNEL=... FC_ROOTFS=... FC_BIN=... tests/scale/validate-launcher.sh [count]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

COUNT="${1:-2}"
WORK="$(mktemp -d /tmp/sam-launcher-XXXXXX)"

export BATS_TEST_NAME="launcher"
export BATS_TEST_NUMBER=0
export BATS_TEST_DIRNAME="${REPO_ROOT}/tests/e2e"
# shellcheck source=/dev/null
source "${REPO_ROOT}/tests/e2e/lib/container_mesh.bash"

cleanup() {
    local status=$?
    echo "==> Tearing down"
    pkill -f "sam-box run --socket ${WORK}/" 2>/dev/null || true
    pkill -f "firecracker --api-sock /tmp/firecracker-vm-" 2>/dev/null || true
    mesh_cleanup_test_resources 2>/dev/null || true
    rm -rf "${WORK}"
    exit "${status}"
}
trap cleanup EXIT

echo "==> Building binaries"
make build >/dev/null

echo "==> Standing up a mesh"
mesh_setup_suite
mesh_setup_env
mesh_start_mock_oidc
mesh_start_router
mesh_start_node 1 "--socket-path /sockets/node.sock --data-dir /sockets/node-data" "" \
    "-v ${MESH_SOCKET_DIR}:/sockets --user $(id -u):$(id -g) -e HOME=/sockets"
mesh_wait_for_log "${MESH_PREFIX}-node-1" "SAM Node Online" 120
mesh_wait_for_mcp_ready 1 30

echo "==> Running the fleet launcher for ${COUNT} sandboxes"
# The node is already up, and the launcher takes an existing socket as an
# existing node, which is the same path a provisioned VM takes on a re-run.
NODE_UDS="${MESH_SOCKET_DIR}/node.sock" \
NODE_DIR="${WORK}/node-data" \
RUN_DIR="${WORK}" \
LOG_DIR="${WORK}" \
SAM_BOX="${REPO_ROOT}/bin/sam-box" \
WORKDIR="${FC_WORKDIR:-/tmp/microvm}" \
AGENT_DOMAIN="validate.sam-mesh.dev" \
    bash "${REPO_ROOT}/scripts/launch-microvms.sh" "${COUNT}"

echo "==> Waiting for the agents to reach the mesh"
# The claim under test: one node, N boundaries, N distinct agents. Anything
# less means a sandbox never got out, and anything more means identities are
# leaking across sandboxes.
#
# Collected the same way the fleet run collects it, so the reporting path is
# exercised here rather than for the first time on a cloud machine.
"${REPO_ROOT}/tests/scale/collect-fleet.sh" \
    --node-socket "${MESH_SOCKET_DIR}/node.sock" \
    --duration 120 --interval 5 --out "${WORK}/fleet.jsonl" || true

seen="$(awk -F'[:,]' '/agents_seen/ {for (i=1;i<=NF;i++) if ($i ~ /"agents_seen"/ && $(i+1)+0 > m) m = $(i+1)+0} END {print m+0}' "${WORK}/fleet.jsonl")"

echo
echo "agents the node is serving: ${seen:-0} (expected ${COUNT})"
if [[ "${seen:-0}" -lt "${COUNT}" ]]; then
    echo "--- boundary logs ---"
    tail -n 5 "${WORK}"/sam-box-vm-*.log 2>/dev/null || true
    echo "--- guest consoles ---"
    grep -ahvE "^\[ *[0-9]+\.[0-9]+\]|^2026-" "${WORK}"/fc-vm-*.log 2>/dev/null | tail -20 || true
    exit 1
fi

echo "OK: ${COUNT} sandboxes, one node, ${seen} distinct agents"
