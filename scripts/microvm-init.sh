#!/bin/sh
# /sbin/init in an agent microVM.
#
# All this does is name the boundary and the agent, because the kernel starts
# init with no arguments. Everything that used to be here -- the tun, the
# routes, the resolver, the proxy plumbing -- is nano-init's job now, in one
# tested binary shared with the container sandbox rather than sixty lines of
# shell that drifted out of step with the design twice.
#
# The boundary is a Unix socket on the host. Firecracker's vsock multiplexes
# guest connections onto "<uds_path>_<port>", so a guest connection to CID 2
# port 1080 arrives on the host at the path sam-box serves.
set -eu

# Best effort, not preconditions: a kernel configured with devtmpfs has already
# mounted /dev by the time init runs, and under `set -e` that redundant mount
# is enough to kill PID 1 before it does anything.
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# The root filesystem is shared read-only by every sandbox on the host, because
# a private 500 MB copy per agent is half a terabyte at a thousand agents and
# the disk is the first thing to run out. Nothing here needs to persist, so the
# few paths that must be writable are given tmpfs and the rest stays shared.
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
if ! touch /etc/.writable 2>/dev/null; then
    mkdir -p /tmp/etc && cp -a /etc/. /tmp/etc/ 2>/dev/null || true
    mount --bind /tmp/etc /etc 2>/dev/null || true
fi
rm -f /etc/.writable 2>/dev/null || true

# The task is only forced when the operator sets one. Left unset, each agent
# image uses its own default, which is what lets the same init boot the polite
# harness and the adversarial agent without knowing which one it is holding.
# Note AGENT_TASK arrives on the kernel cmdline, so it cannot contain spaces;
# a real prompt belongs in the agent image, not here.
if [ -n "${AGENT_TASK:-}" ]; then
    set -- "${AGENT_TASK}"
else
    set --
fi

# The kernel hands PID 1 an empty environment, so there is no PATH to inherit
# and anything looked up by name is not found.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Not exec: when PID 1 exits the kernel panics immediately, and the panic
# reaches the console before whatever init was trying to say about why it
# failed. Holding the process open long enough for the console to drain is the
# difference between a diagnosis and a stack trace.
if ! /usr/local/bin/nano-init run vsock://2:1080 python3 /app/agent/agent.py "$@" > /dev/console 2>&1; then
  echo "sandbox init failed; see above" > /dev/console
fi

# A density measurement needs the population to exist at the same time. Left to
# itself a sandbox powers off the moment its agent is done, so a thousand of
# them started in sequence are never a thousand at once, and the memory figure
# would describe how many passed through rather than how many fit.
if [ "${SANDBOX_LINGER:-0}" -gt 0 ] 2>/dev/null; then
  echo "Agent finished; holding the sandbox for ${SANDBOX_LINGER}s." > /dev/console
  sleep "${SANDBOX_LINGER}"
fi

sleep 3
reboot -f
