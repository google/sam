#!/usr/bin/env bats

# The microVM datapath, end to end, with a real kernel booting a real guest.
#
# Everything else about the sandbox is covered more cheaply elsewhere: the
# boundary has unit tests, the routed container path has agent_sandbox.bats, and
# the vsock dialer is exercised against loopback in the nano-init module. What
# none of those touch is the one arrangement the scale run depends on -- a guest
# with no network device reaching a Unix socket on the host through Firecracker's
# vsock, where the host side is named "<uds_path>_<port>" and getting that name
# wrong fails silently.
#
# This deliberately does not stand up a mesh. A mesh would make the test slower
# and would not make it prove anything more: what is in question is whether a
# microVM can reach the boundary at all.
#
# FC_MEM_MIB sizes the guest, defaulting to 160: the smallest size measured to
# run the example Python harness at full speed. Raise it for a heavier agent,
# and see tests/scale/measure-guest.sh to measure your own.

load "lib/container_mesh.bash"

FC_DIR=""
FC_PID=""

setup() {
  command -v firecracker >/dev/null 2>&1 || skip "firecracker is not installed"
  [[ -r /dev/kvm && -w /dev/kvm ]] || skip "no writable /dev/kvm on this machine"

  local kernel="${FC_KERNEL:-/opt/microvm/vmlinux.bin}"
  [[ -f "${kernel}" ]] || skip "no guest kernel; set FC_KERNEL"
  [[ -f "${FC_ROOTFS:-/opt/microvm/rootfs.ext4}" ]] || skip "no guest rootfs; set FC_ROOTFS (scripts/build-rootfs.sh)"

  # An agent sandbox needs a tun to have any route at all, and the stock
  # Firecracker CI kernels are built without CONFIG_TUN: they carry vsock and
  # virtio and nothing else. Checked here because the alternative is a guest
  # that panics with its explanation truncated by the panic itself.
  #
  # grep reads the binary directly rather than piping strings, which is not
  # installed everywhere; a check that cannot run must not report a failure.
  local tun_driver
  tun_driver="$(grep -ac "Universal TUN/TAP" "${kernel}" 2>/dev/null || true)"
  [[ "${tun_driver}" -gt 0 ]] \
    || skip "guest kernel has no TUN driver; agent sandboxes need CONFIG_TUN"

  FC_DIR="$(mktemp -d /tmp/fc-smoke-XXXXXX)"
}

teardown() {
  [[ -n "${FC_PID}" ]] && kill "${FC_PID}" 2>/dev/null
  [[ -n "${FC_DIR}" ]] && rm -rf "${FC_DIR}"
  return 0
}

fc_put() {
  curl -sf -X PUT --unix-socket "${FC_DIR}/fc.sock" \
    "http://localhost$1" -H 'Content-Type: application/json' -d "$2" >/dev/null
}

@test "a microVM with no network device reaches the boundary over vsock" {
  local kernel="${FC_KERNEL:-/opt/microvm/vmlinux.bin}"
  local rootfs="${FC_ROOTFS:-/opt/microvm/rootfs.ext4}"

  # The boundary stands in for sam-box: it only has to accept, because what is
  # being tested is whether a connection arrives at all. Firecracker multiplexes
  # guest connections onto "<uds>_<port>", so this listens on the port-suffixed
  # name and nothing else will do.
  local vsock_uds="${FC_DIR}/vm.vsock"
  socat -u "UNIX-LISTEN:${vsock_uds}_1080,fork" "CREATE:${FC_DIR}/arrived" &
  local boundary_pid=$!

  cp "${rootfs}" "${FC_DIR}/rootfs.ext4"

  firecracker --api-sock "${FC_DIR}/fc.sock" >"${FC_DIR}/fc.log" 2>&1 &
  FC_PID=$!

  local waited=0
  until [[ -S "${FC_DIR}/fc.sock" ]]; do
    sleep 0.1
    waited=$((waited + 1))
    [[ "${waited}" -lt 50 ]] || {
      cat "${FC_DIR}/fc.log"
      false
    }
  done

  fc_put /boot-source "{
    \"kernel_image_path\": \"${kernel}\",
    \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"
  }"
  fc_put /machine-config "{ \"vcpu_count\": ${FC_VCPUS:-1}, \"mem_size_mib\": ${FC_MEM_MIB:-160} }"
  fc_put /drives/rootfs "{
    \"drive_id\": \"rootfs\",
    \"path_on_host\": \"${FC_DIR}/rootfs.ext4\",
    \"is_root_device\": true,
    \"is_read_only\": false
  }"
  fc_put /vsock "{
    \"vsock_id\": \"vsock0\",
    \"guest_cid\": 3,
    \"uds_path\": \"${vsock_uds}\"
  }"
  fc_put /actions '{ "action_type": "InstanceStart" }'

  # The guest boots, nano-init builds its tun and the agent resolves a mesh
  # name, which can only leave through vsock. Something arriving here means the
  # whole chain worked: no NIC in the guest, a route through tun0, gVisor
  # terminating the connection, and the host side named correctly.
  waited=0
  until [[ -s "${FC_DIR}/arrived" ]]; do
    sleep 0.5
    waited=$((waited + 1))
    [[ "${waited}" -lt 120 ]] || {
      echo "nothing reached the boundary in 60s"
      echo "--- firecracker ---"
      cat "${FC_DIR}/fc.log"
      kill "${boundary_pid}" 2>/dev/null
      false
    }
  done

  kill "${boundary_pid}" 2>/dev/null

  # A SOCKS5 greeting, which is what nano-init opens with. Anything else means
  # something arrived but it was not the boundary protocol.
  run head -c 1 "${FC_DIR}/arrived"
  [[ "$status" -eq 0 ]]
  printf '%s' "$output" | od -An -tu1 | grep -qE '\<5\>' || {
    echo "first byte was not a SOCKS5 version marker:"
    od -An -tx1 -N16 "${FC_DIR}/arrived"
    false
  }
}
