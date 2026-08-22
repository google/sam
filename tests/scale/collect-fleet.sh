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
# Watch a fleet of agent sandboxes come up.
#
# The headline number for a run like this is how many agents the mesh is
# actually serving, and it is not the number of microVMs somebody started: a
# guest that booted and never reached the boundary is not an agent, it is a
# process. So this asks the node, which is the only party that knows, and
# samples it over time rather than once at the end -- the shape of the curve is
# what says whether a population came up smoothly or fell over partway.
#
# Alongside it, what the fleet costs the host. Resident memory is summed per
# process class rather than taken from the machine total, so a run can say what
# an agent cost rather than what was left over.
#
# Usage:
#   tests/scale/collect-fleet.sh --node-socket /var/run/sam-node.sock \
#     --duration 300 --out results.jsonl

set -euo pipefail

NODE_SOCKET="/var/run/sam-node.sock"
DURATION=300
INTERVAL=5
OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node-socket) NODE_SOCKET="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        -h|--help) sed -n '17,32p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

OUT="${OUT:-fleet-$(date +%Y%m%dT%H%M%S).jsonl}"

# Resident, not configured. A guest's mem_size_mib is a ceiling; what the host
# pays is the pages it touched, and that is what density is built from.
rss_total() {
    local pattern="$1" total=0 pid
    for pid in $(pgrep -f "${pattern}" 2>/dev/null || true); do
        local kb
        kb="$(awk '/VmRSS/ {print $2}' "/proc/${pid}/status" 2>/dev/null || echo 0)"
        total=$((total + ${kb:-0}))
    done
    echo "${total}"
}

# pgrep -c prints 0 AND exits non-zero when nothing matches, so a `|| echo 0`
# fallback emits it twice and quietly corrupts the JSON.
count_of() {
    local n
    n="$(pgrep -cf "$1" 2>/dev/null)"
    echo "${n:-0}"
}

# Nothing below may abort the run: a sample that could not be taken is a zero,
# not a reason to stop watching a fleet that took minutes to start.
set +e

# The node counts distinct agents it has served for a local gateway, which is
# the closest thing to "agents in the mesh" that anything can honestly report.
#
# The curl is guarded because a scrape that fails must produce a zero sample
# rather than end the collection: under pipefail a failed curl fails the whole
# pipeline, and a collector that dies the first time the node is briefly busy
# is worse than no collector.
scrape() {
    curl -s --max-time 5 --unix-socket "${NODE_SOCKET}" http://localhost/metrics 2>/dev/null || true
}

agents_seen() {
    scrape | awk '/^sam_node_agents_seen /{printf "%d", $2; found=1} END{if(!found) printf "0"}'
}

node_metric() {
    scrape | awk -v m="$1" '$1 == m {printf "%d", $2; found=1} END{if(!found) printf "0"}'
}

echo "collecting every ${INTERVAL}s for ${DURATION}s into ${OUT}" >&2
printf '%-9s %-8s %-8s %-10s %-10s\n' "elapsed" "agents" "microvms" "guest_gib" "box_gib" >&2

started="$(date +%s)"
: > "${OUT}"

while :; do
    now="$(date +%s)"
    elapsed=$((now - started))
    [[ "${elapsed}" -ge "${DURATION}" ]] && break

    agents="$(agents_seen)"
    vms="$(count_of 'firecracker --api-sock')"
    boxes="$(count_of 'sam-box run --socket')"
    vm_rss_kb="$(rss_total 'firecracker --api-sock')"
    box_rss_kb="$(rss_total 'sam-box run --socket')"
    node_rss_kb="$(rss_total 'sam-node run')"
    mem_avail_kb="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"
    load="$(awk '{print $1}' /proc/loadavg)"

    printf '{"elapsed_s":%d,"agents_seen":%s,"microvms":%s,"boundaries":%s,' \
        "${elapsed}" "${agents:-0}" "${vms:-0}" "${boxes:-0}" >> "${OUT}"
    printf '"guest_rss_kb":%s,"boundary_rss_kb":%s,"node_rss_kb":%s,' \
        "${vm_rss_kb}" "${box_rss_kb}" "${node_rss_kb}" >> "${OUT}"
    printf '"mem_available_kb":%s,"load1":%s,"requests_in_flight":%s}\n' \
        "${mem_avail_kb}" "${load}" "$(node_metric sam_node_requests_in_flight)" >> "${OUT}"

    printf '%-9s %-8s %-8s %-10s %-10s\n' \
        "${elapsed}s" "${agents:-0}" "${vms:-0}" \
        "$(awk -v k="${vm_rss_kb}" 'BEGIN{printf "%.2f", k/1048576}')" \
        "$(awk -v k="${box_rss_kb}" 'BEGIN{printf "%.2f", k/1048576}')" >&2

    sleep "${INTERVAL}"
done

echo >&2
echo "=== summary ===" >&2
awk -F'[:,]' '
    /agents_seen/ {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /"agents_seen"/) a = $(i+1)
            if ($i ~ /"microvms"/) v = $(i+1)
            if ($i ~ /"guest_rss_kb"/) g = $(i+1)
            if ($i ~ /"boundary_rss_kb"/) b = $(i+1)
        }
        if (a > maxa) { maxa = a; maxg = g; maxb = b; maxv = v }
    }
    END {
        printf "peak agents served:   %d\n", maxa
        printf "microVMs at peak:     %d\n", maxv
        if (maxa > 0) {
            printf "guest memory:         %.2f GiB (%.0f MiB per agent)\n", maxg/1048576, maxg/1024/maxa
            printf "boundary memory:      %.2f GiB (%.0f MiB per agent)\n", maxb/1048576, maxb/1024/maxa
            printf "total per agent:      %.0f MiB\n", (maxg+maxb)/1024/maxa
        }
    }
' "${OUT}" >&2

echo >&2
echo "samples in ${OUT}" >&2
