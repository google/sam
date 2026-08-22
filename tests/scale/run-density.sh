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
# What does the Nth agent cost?
#
# The design says an agent is a principal with its own boundary, which is only
# affordable if a boundary is cheap. This measures that directly: it stands up
# one real mesh, attaches sandbox boundaries to it one at a time, and at each
# step records what the new one cost to start, what it costs to keep, and
# whether the ones already running got slower.
#
# It deliberately runs the boundaries as host processes rather than containers.
# The question is what sam-box costs, and wrapping each one in a container would
# measure the container runtime instead.
#
# Usage:
#   tests/scale/run-density.sh [--steps 1,2,4,8,16,32] [--requests 200] [--out DIR]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

STEPS="1,2,4,8,16,32"
REQUESTS=200
CONCURRENCY=4
WARMUP=20
OUT_DIR=""
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --steps) STEPS="$2"; shift 2 ;;
    --requests) REQUESTS="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '17,31p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

OUT_DIR="${OUT_DIR:-${REPO_ROOT}/tests/scale/results/$(date +%Y%m%dT%H%M%S)}"
mkdir -p "${OUT_DIR}"

# The boundaries are host processes, so their sockets and metrics ports are too.
BOX_PIDS=()
BOX_DIR="$(mktemp -d /tmp/sam-scale-XXXXXX)"

# Pick a metrics port range that is actually free. A previous run that leaked
# its processes would otherwise make this one fail on its first sandbox, and
# that failure reads as a defect in sam-box rather than in the harness.
pick_port_base() {
  local base
  for base in 19600 19700 19800 19900 20000; do
    if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":($((base + 1)))\$"; then
      echo "${base}"
      return 0
    fi
  done
  echo "no free metrics port range; is a previous run still going?" >&2
  return 1
}
METRICS_BASE="$(pick_port_base)"

# The mesh helpers are written for bats but only need a few of its variables:
# two to name things and one to find the repo root it builds images from.
export BATS_TEST_NAME="scale"
export BATS_TEST_NUMBER=0
export BATS_TEST_DIRNAME="${REPO_ROOT}/tests/e2e"
# shellcheck source=/dev/null
source "${REPO_ROOT}/tests/e2e/lib/container_mesh.bash"

cleanup() {
  local status=$?
  echo "==> Tearing down"
  for pid in "${BOX_PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  # The recorded pids are the reliable path; this catches anything that
  # outlived its record, so a failed run cannot leave sandboxes holding ports
  # and make the next run look broken.
  pkill -f "sam-box run --socket ${BOX_DIR}/" 2>/dev/null || true
  mesh_cleanup_test_resources 2>/dev/null || true
  [[ "${KEEP}" -eq 1 ]] || rm -rf "${BOX_DIR}"
  exit "${status}"
}
trap cleanup EXIT

# record_environment writes down what the numbers were produced on, because a
# latency without a machine attached to it is not a result.
record_environment() {
  {
    echo "{"
    printf '  "recorded": "%s",\n' "$(date -Is)"
    printf '  "commit": "%s",\n' "$(git rev-parse HEAD)"
    printf '  "dirty": %s,\n' "$([[ -z "$(git status --porcelain)" ]] && echo false || echo true)"
    printf '  "kernel": "%s",\n' "$(uname -sr)"
    printf '  "cpus": %s,\n' "$(nproc)"
    printf '  "memory_kb": %s,\n' "$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    printf '  "cpu_model": "%s",\n' "$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
    printf '  "go": "%s"\n' "$(go version | awk '{print $3}')"
    echo "}"
  } > "${OUT_DIR}/environment.json"
}

# start_box attaches one more sandbox boundary and reports how long it took to
# become usable, in milliseconds, through STARTUP_MS. It sets a global rather
# than printing one, because a command substitution would run it in a subshell
# and the pid it records would die with that subshell, leaving the boundary
# running with nothing left to kill it by.
STARTUP_MS=0
start_box() {
  local index="$1"
  local socket="${BOX_DIR}/agent-${index}.sock"
  local port=$((METRICS_BASE + index))
  local started
  started="$(date +%s%N)"

  "${REPO_ROOT}/bin/sam-box" run \
    --socket "${socket}" \
    --sidecar-socket "${MESH_SOCKET_DIR}/node.sock" \
    --metrics-addr "127.0.0.1:${port}" \
    --egress-allow example.invalid \
    > "${BOX_DIR}/box-${index}.log" 2>&1 &
  BOX_PIDS+=("$!")

  # Readiness is the socket accepting a connection, not the process existing:
  # a boundary that has not bound its socket yet is of no use to the agent
  # waiting on it.
  local waited=0
  while [[ ! -S "${socket}" ]]; do
    sleep 0.01
    waited=$((waited + 1))
    if [[ "${waited}" -gt 3000 ]]; then
      echo "boundary ${index} never bound its socket" >&2
      cat "${BOX_DIR}/box-${index}.log" >&2
      return 1
    fi
  done

  STARTUP_MS=$((($(date +%s%N) - started) / 1000000))
}

echo "==> Recording environment"
record_environment

echo "==> Building binaries"
make build >/dev/null

echo "==> Standing up the mesh"
mesh_setup_suite
mesh_setup_env
mesh_start_mock_oidc
mesh_start_router
mesh_start_node 1 "--socket-path /sockets/node.sock --data-dir /sockets/node-data" "" \
  "-v ${MESH_SOCKET_DIR}:/sockets --user $(id -u):$(id -g) -e HOME=/sockets"
mesh_wait_for_log "${MESH_PREFIX}-node-1" "SAM Node Online" 120
mesh_wait_for_mcp_ready 1 30

echo "==> Sweeping ${STEPS} sandboxes"
: > "${OUT_DIR}/startup.csv"
echo "index,startup_ms" >> "${OUT_DIR}/startup.csv"

# The baseline is the same node answering the same request with no boundary in
# the path. Without it the mesh numbers are unanchored: a millisecond means
# nothing until something says what a millisecond buys. It dials the node's
# socket directly, because putting a relay there to give it a TCP address would
# add a userspace hop to the baseline and flatter everything compared to it.
echo "==> Measuring the baseline, no boundary"
"${REPO_ROOT}/bin/sam-bench" run \
  --target-unix "${MESH_SOCKET_DIR}/node.sock" \
  --target "http://localhost/v1/models" \
  --requests "${REQUESTS}" \
  --concurrency "${CONCURRENCY}" \
  --warmup "${WARMUP}" \
  --label "agents=0" \
  --label "condition=no-boundary" \
  --out "${OUT_DIR}/baseline.json" || echo "baseline unavailable, continuing"

running=0
for step in ${STEPS//,/ }; do
  while [[ "${running}" -lt "${step}" ]]; do
    running=$((running + 1))
    start_box "${running}"
    echo "${running},${STARTUP_MS}" >> "${OUT_DIR}/startup.csv"
  done

  echo "--> ${running} sandboxes attached; measuring"

  # Every boundary is scraped, so the recorded cost is the whole population's,
  # not a sample that happens to be idle.
  scrape_args=()
  for i in $(seq 1 "${running}"); do
    scrape_args+=(--scrape "http://127.0.0.1:$((METRICS_BASE + i))/metrics")
  done

  # Load goes through the first boundary while all of them are attached, so a
  # slowdown caused by the others shows up where it would be felt.
  #
  # Twice, because reusing a connection and opening one are different
  # questions. A kept-alive flow is admitted once and carries every request
  # after that for free; a new flow per request pays the SOCKS5 handshake and
  # the policy decision every time. Only the second measures what enforcement
  # costs, and only the first describes how an agent normally behaves.
  for condition in reused-flow new-flow-per-request; do
    flag=()
    [[ "${condition}" == "new-flow-per-request" ]] && flag=(--new-flow-per-request)

    "${REPO_ROOT}/bin/sam-bench" run \
      --socket "${BOX_DIR}/agent-1.sock" \
      --target "http://mesh.sam.alt/v1/models" \
      --requests "${REQUESTS}" \
      --concurrency "${CONCURRENCY}" \
      --warmup "${WARMUP}" \
      --label "agents=${running}" \
      --label "condition=${condition}" \
      "${flag[@]}" \
      "${scrape_args[@]}" \
      --out "${OUT_DIR}/${condition}-$(printf '%04d' "${running}").json"
  done

  # Enforcement, measured rather than asserted. The same boundary, under the
  # same load, asked for somewhere policy does not allow. Every one of these
  # must fail, and a run where any succeeded is a security result, not a
  # performance one, so it is recorded next to the latencies rather than in a
  # separate place nobody reads.
  "${REPO_ROOT}/bin/sam-bench" run \
    --socket "${BOX_DIR}/agent-1.sock" \
    --target "http://blocked.example.com/v1/models" \
    --requests "${REQUESTS}" \
    --concurrency "${CONCURRENCY}" \
    --warmup 0 \
    --label "agents=${running}" \
    --label "condition=denied" \
    "${scrape_args[@]}" \
    --out "${OUT_DIR}/denied-$(printf '%04d' "${running}").json"
done

echo "==> Results in ${OUT_DIR}"
{
  echo "### Reused flow: what an agent normally experiences"
  echo
  "${REPO_ROOT}/bin/sam-bench" report \
    --gauge "process_resident_memory_bytes" \
    "${OUT_DIR}"/reused-flow-*.json
  echo
  echo "### New flow per request: what admission costs"
  echo
  "${REPO_ROOT}/bin/sam-bench" report \
    --metric "sam_box_flows_total{outcome=allowed,route=mesh-entrypoint}" \
    "${OUT_DIR}"/new-flow-per-request-*.json
  echo
  echo "### Denied: what enforcement costs, and that it held"
  echo
  "${REPO_ROOT}/bin/sam-bench" report \
    --metric "sam_box_flows_total{outcome=denied,route=unresolved}" \
    "${OUT_DIR}"/denied-*.json
  if [[ -f "${OUT_DIR}/baseline.json" ]]; then
    echo
    echo "### Baseline: the same node, no boundary"
    echo
    "${REPO_ROOT}/bin/sam-bench" report "${OUT_DIR}/baseline.json"
  fi
} | tee "${OUT_DIR}/table.md"
