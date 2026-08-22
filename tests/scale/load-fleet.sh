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
# Drive load through a resident fleet of agent boundaries.
#
# A density result says how many agents fit; it says nothing about what they can
# do once they are there. This drives real requests through a fleet that is
# already up, so throughput is measured against the same population that was
# counted rather than against a fresh, empty host.
#
# The important detail is that load goes through one boundary per agent rather
# than many connections through one. Each sam-box carries its own agent's
# identity, so the node sees N distinct principals and the admission path is
# exercised the way it would be in practice. Pointing a single load generator at
# a single boundary would measure a socket, not a mesh.
#
# Load is driven from the host into the boundary's SOCKS5 socket. That is the
# same entry point the guest uses over vsock, but it skips the in-guest netstack
# and the vsock hop, so these numbers bound the mesh datapath and not the
# sandbox's own overhead.
#
# Usage:
#   tests/scale/load-fleet.sh --agents 200 --requests 200 --out /var/log/load
#
# Then aggregate with:
#   tests/scale/load-fleet.sh --report /var/log/load

set -euo pipefail

AGENTS=200
REQUESTS=200
CONCURRENCY=2
WARMUP=5
OUT="/var/log/load"
TARGET="http://mesh.sam.alt/v1/models"
SOCKET_PREFIX="/var/run/sam-vm"
SOCKET_SUFFIX=".vsock_1080"
SAM_BENCH="${SAM_BENCH:-sam-bench}"
REPORT_ONLY=""

usage() {
  cat <<'EOF'
Drive load through a resident fleet of agent boundaries.

Options:
  --agents N        boundaries to drive concurrently (default 200)
  --requests N      requests per agent (default 200)
  --concurrency N   in-flight requests per agent (default 2)
  --warmup N        unmeasured requests per agent (default 5)
  --target URL      mesh URL to request (default http://mesh.sam.alt/v1/models)
  --out DIR         where per-agent JSON lands (default /var/log/load)
  --report DIR      aggregate an existing result directory and exit
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agents) AGENTS="$2"; shift 2 ;;
    --requests) REQUESTS="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --report) REPORT_ONLY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

aggregate() {
  local dir="$1"
  python3 - "$dir" <<'PYEOF'
import json, glob, statistics, sys
from datetime import datetime

files = sorted(glob.glob(f"{sys.argv[1]}/agent-*.json"))
if not files:
    sys.exit("no per-agent results found")

starts, ends, rps, p50, p95, p99, worst, cold = [], [], [], [], [], [], [], []
ok = failed = 0
for path in files:
    doc = json.load(open(path))
    rep = doc["report"]
    started = datetime.fromisoformat(doc["started"].replace("Z", "+00:00")).timestamp()
    starts.append(started)
    ends.append(started + rep["elapsed_seconds"])
    ok += rep["succeeded"]
    failed += rep["failed"]
    rps.append(rep["requests_per_second"])
    t = rep["ttfb_ms"]
    p50.append(t["p50"]); p95.append(t["p95"]); p99.append(t["p99"]); worst.append(t["max"])
    cold.append(rep["warmup_ttfb_ms"]["max"])

wall = max(ends) - min(starts)
med = statistics.median
print(f"agents driving load  : {len(files)}")
print(f"requests             : {ok} ok / {failed} failed")
print(f"wall clock           : {wall:.2f} s")
print(f"aggregate throughput : {ok / wall:,.0f} req/s")
print(f"per-agent rps        : median {med(rps):.0f}  min {min(rps):.0f}  max {max(rps):.0f}")
print(f"ttfb p50             : median {med(p50):.2f} ms  worst agent {max(p50):.2f} ms")
print(f"ttfb p95             : median {med(p95):.2f} ms  worst agent {max(p95):.2f} ms")
print(f"ttfb p99             : median {med(p99):.2f} ms  worst agent {max(p99):.2f} ms")
print(f"worst single request : {max(worst):.2f} ms")
print(f"cold start (warmup)  : median {med(cold):.0f} ms  max {max(cold):.0f} ms")
PYEOF
}

if [[ -n "$REPORT_ONLY" ]]; then
  aggregate "$REPORT_ONLY"
  exit 0
fi

command -v "$SAM_BENCH" >/dev/null 2>&1 || {
  echo "sam-bench not found; build it with 'go build ./cmd/sam-bench' or set SAM_BENCH" >&2
  exit 1
}

# Fail early rather than after spawning a few hundred hopeless processes.
missing=0
for i in $(seq 1 "$AGENTS"); do
  [[ -S "${SOCKET_PREFIX}-${i}${SOCKET_SUFFIX}" ]] || missing=$((missing + 1))
done
if (( missing > 0 )); then
  echo "missing $missing of $AGENTS boundary sockets under ${SOCKET_PREFIX}-N${SOCKET_SUFFIX}" >&2
  echo "is the fleet still resident? check with: pgrep -c sam-box" >&2
  exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/agent-*.json

echo "driving $AGENTS agents x $REQUESTS requests at $TARGET"
for i in $(seq 1 "$AGENTS"); do
  "$SAM_BENCH" run \
    --socket "${SOCKET_PREFIX}-${i}${SOCKET_SUFFIX}" \
    --target "$TARGET" \
    --requests "$REQUESTS" \
    --concurrency "$CONCURRENCY" \
    --warmup "$WARMUP" \
    --label "agent=$i" \
    --out "$OUT/agent-$i.json" >/dev/null 2>&1 &
done
wait

echo
aggregate "$OUT"
