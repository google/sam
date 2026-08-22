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
# What does one agent sandbox actually need?
#
# How many agents fit on a host is decided by a number somebody has to choose,
# and choosing it by guesswork is how a scale run ends up either wasting most of
# a machine or dying halfway through. This measures it: the guest is booted at
# decreasing memory sizes and asked whether an agent still gets as far as
# opening a flow to the boundary.
#
# It reports three things per size. Whether it worked at all, how long the guest
# took from start to that first flow -- a size that technically works but boots
# slowly is a size under pressure -- and what the microVM cost the host, which
# is the figure density is actually built from.
#
# The numbers describe whatever agent is in the rootfs. Re-run it against your
# own rather than trusting a table written for someone else's.
#
# Usage:
#   FC_KERNEL=... FC_ROOTFS=... tests/scale/measure-guest.sh
#   SIZES="256 192 160" tests/scale/measure-guest.sh

set -uo pipefail

KERNEL="${FC_KERNEL:-/opt/microvm/vmlinux.bin}"
ROOTFS="${FC_ROOTFS:-/opt/microvm/rootfs.ext4}"
FC="${FC_BIN:-firecracker}"
SIZES="${SIZES:-512 384 256 192 160 144 136 128}"

command -v "${FC}" >/dev/null 2>&1 || { echo "firecracker not found; set FC_BIN" >&2; exit 1; }
[[ -f "${KERNEL}" ]] || { echo "no kernel at ${KERNEL}; set FC_KERNEL" >&2; exit 1; }
[[ -f "${ROOTFS}" ]] || { echo "no rootfs at ${ROOTFS}; set FC_ROOTFS" >&2; exit 1; }

# An agent sandbox has no network device and reaches the mesh through a tun, so
# a kernel without the driver gives it no route and this measures nothing.
#
# grep reads the binary directly rather than piping strings, which is not
# installed everywhere; a check that cannot run must not report a failure.
tun_driver="$(grep -ac "Universal TUN/TAP" "${KERNEL}" 2>/dev/null || true)"
if [[ "${tun_driver}" -eq 0 ]]; then
    echo "guest kernel has no TUN driver; agent sandboxes need CONFIG_TUN" >&2
    exit 1
fi

printf '%-9s %-9s %-14s %s\n' "mem_mib" "reached" "boot_to_flow" "host_rss_mib"

for mem in ${SIZES}; do
    dir="$(mktemp -d /tmp/sam-guest-size-XXXXXX)"
    cp "${ROOTFS}" "${dir}/rootfs.ext4"

    # Stands in for sam-box: the flow only has to arrive, because what is being
    # measured is whether the guest had enough memory to get that far.
    socat -u "UNIX-LISTEN:${dir}/vm.vsock_1080,fork" "CREATE:${dir}/arrived" &
    socat_pid=$!

    "${FC}" --api-sock "${dir}/fc.sock" >"${dir}/fc.log" 2>&1 &
    fc_pid=$!
    for _ in $(seq 1 50); do [[ -S "${dir}/fc.sock" ]] && break; sleep 0.1; done

    put() {
        curl -sf -X PUT --unix-socket "${dir}/fc.sock" "http://localhost$1" \
            -H 'Content-Type: application/json' -d "$2" >/dev/null
    }

    put /boot-source "{\"kernel_image_path\":\"${KERNEL}\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off\"}"
    put /machine-config "{\"vcpu_count\":${VM_VCPUS:-1},\"mem_size_mib\":${mem}}"
    put /drives/rootfs "{\"drive_id\":\"rootfs\",\"path_on_host\":\"${dir}/rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}"
    put /vsock "{\"vsock_id\":\"vsock0\",\"guest_cid\":3,\"uds_path\":\"${dir}/vm.vsock\"}"

    started="$(date +%s%N)"
    put /actions '{"action_type":"InstanceStart"}'

    reached="no"
    elapsed="-"
    for _ in $(seq 1 120); do
        if [[ -s "${dir}/arrived" ]]; then
            reached="yes"
            elapsed="$((($(date +%s%N) - started) / 1000000))ms"
            break
        fi
        # A guest that panicked is not going to recover; stop waiting on it.
        kill -0 "${fc_pid}" 2>/dev/null || break
        sleep 0.25
    done

    # Resident, not configured: the host pays for pages the guest touched, so
    # this is what density is built from rather than mem_size_mib.
    rss="-"
    if kill -0 "${fc_pid}" 2>/dev/null; then
        rss="$(awk '/VmRSS/ {printf "%.0f", $2/1024}' "/proc/${fc_pid}/status" 2>/dev/null || echo -)"
    fi

    printf '%-9s %-9s %-14s %s\n' "${mem}" "${reached}" "${elapsed}" "${rss}"

    kill "${fc_pid}" "${socat_pid}" 2>/dev/null
    wait "${fc_pid}" 2>/dev/null
    rm -rf "${dir}"
done
