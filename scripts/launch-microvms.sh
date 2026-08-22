#!/bin/bash
# Launch N agent sandboxes on one host.
#
# The shape here is the point, and it is not what this script used to do. It
# ran one sam-node per microVM, which made every agent a mesh member: its own
# enrolment, its own libp2p host, its own place in the DHT. That does not reach
# a thousand agents on a host, and it measures the wrong thing besides. An
# agent is a principal, not a peer.
#
# So: one sam-node for the host, which is the mesh member, and one sam-box per
# agent, which holds no mesh identity at all and names its agent on every
# request. Adding an agent costs a boundary, not an enrolment.
set -euo pipefail

COUNT=${1:-1}
WORKDIR="${WORKDIR:-/opt/microvm}"
CONTROL_PLANE="${CONTROL_PLANE:-https://bananas.sam-mesh.dev}"
AGENT_DOMAIN="${AGENT_DOMAIN:-scale.sam-mesh.dev}"

# Firecracker defaults to 128 MiB, which silently decides how many agents fit
# on a host. Saying it out loud makes density a parameter of the experiment
# rather than a property of the tool.
#
# 160 is the smallest size measured to run the example Python harness at full
# speed: 144 works but boots a second slower for being cramped, and 136 never
# reaches the boundary at all. A heavier agent needs more, so measure your own
# rootfs with tests/scale/measure-guest.sh rather than trusting a number
# written for this one.
#
# Worth knowing when budgeting: mem_size_mib is a ceiling, not an allocation.
# The host only pays for pages the guest touches, so raising it is cheap and
# the real cost per agent is roughly the guest's working set plus about 18 MiB
# for its sam-box.
VM_MEM_MIB="${VM_MEM_MIB:-160}"
VM_VCPUS="${VM_VCPUS:-1}"

# How long a sandbox stays up after its agent finishes. A density measurement
# needs the population resident at the same time, and left alone a sandbox
# powers off the moment it is done -- so a thousand started in sequence are
# never a thousand at once. Zero is the right default for real work.
SANDBOX_LINGER="${SANDBOX_LINGER:-0}"

# Anything the agent needs to know reaches it as a kernel cmdline pair, so it
# must not contain spaces: the kernel splits on them and init would see two
# variables. Model names and durations are safe; prompts are not, which is why
# the task stays in the init script.
AGENT_ENV=""
for v in SAM_MODEL CHAOS_SLEEP CHAOS_ROUNDS; do
    eval "val=\${$v:-}"
    [ -z "$val" ] && continue
    case "$val" in
        *" "*) echo "Error: $v must not contain spaces (kernel cmdline)" >&2; exit 1 ;;
    esac
    AGENT_ENV="$AGENT_ENV $v=$val"
done

if [ ! -d "$WORKDIR" ]; then
    echo "Error: $WORKDIR does not exist. Did cloud-init finish?" >&2
    exit 1
fi

# Everything the host writes is overridable, so this can be exercised on a
# workstation before it is trusted on a fleet. The defaults are the paths a
# provisioned VM has.
NODE_UDS="${NODE_UDS:-/var/run/sam-node.sock}"
NODE_DIR="${NODE_DIR:-/var/lib/sam-node}"
RUN_DIR="${RUN_DIR:-/var/run}"
LOG_DIR="${LOG_DIR:-/var/log}"
SAM_NODE="${SAM_NODE:-sam-node}"
SAM_BOX="${SAM_BOX:-sam-box}"
BOOTSTRAP_TOKEN_PATH="${BOOTSTRAP_TOKEN_PATH:-/etc/sam-bootstrap-token}"

# Everything is checked before anything is started. Launching a thousand
# sandboxes against a node that turned out to be unenrollable wastes the whole
# run and reports it as a boundary problem, and a token file that exists but is
# empty produces a node that quietly waits to be enrolled forever rather than
# an error anyone can act on.
preflight_failed=0
fail() { echo "preflight: $*" >&2; preflight_failed=1; }

command -v firecracker >/dev/null 2>&1 || fail "firecracker is not installed"
[ -w /dev/kvm ] || fail "/dev/kvm is not writable; nested virtualisation is required"
[ -f "$WORKDIR/vmlinux.bin" ] || fail "no guest kernel at $WORKDIR/vmlinux.bin"
[ -f "$WORKDIR/rootfs.ext4" ] || fail "no guest rootfs at $WORKDIR/rootfs.ext4"
command -v "$SAM_BOX" >/dev/null 2>&1 || [ -x "$SAM_BOX" ] || fail "sam-box not found ($SAM_BOX)"

# An agent sandbox has no network device and reaches the mesh through a tun, so
# a kernel without the driver gives every sandbox no route at all.
#
# grep reads the binary directly rather than piping strings, which is not
# installed everywhere: a check that cannot run must not report that the check
# failed, and this one did exactly that on a host without binutils.
if [ -f "$WORKDIR/vmlinux.bin" ]; then
    tun_driver="$(grep -ac "Universal TUN/TAP" "$WORKDIR/vmlinux.bin" 2>/dev/null || true)"
    [ "${tun_driver:-0}" -gt 0 ] || fail "guest kernel has no TUN driver; sandboxes need CONFIG_TUN"
fi

# A node that is already serving needs no credential. One that has to be
# started does, and finding that out after a fleet is up is too late.
if [ ! -S "$NODE_UDS" ]; then
    command -v "$SAM_NODE" >/dev/null 2>&1 || [ -x "$SAM_NODE" ] || fail "sam-node not found ($SAM_NODE)"
    if [ ! -s "$BOOTSTRAP_TOKEN_PATH" ]; then
        fail "no bootstrap token at $BOOTSTRAP_TOKEN_PATH (set BOOTSTRAP_TOKEN_PATH), and no node already serving $NODE_UDS"
    fi
fi

if [ "$preflight_failed" -ne 0 ]; then
    echo "preflight: refusing to start anything" >&2
    exit 1
fi

mkdir -p "${RUN_DIR}" "${LOG_DIR}"

echo "=== One node for the host ==="
# An existing socket is taken as an existing node. That makes this safe to run
# twice, and lets an operator start the node however their environment needs
# rather than only the way this script would.
if [ -S "${NODE_UDS}" ]; then
    echo "Using the node already serving ${NODE_UDS}"
else
    mkdir -p "${NODE_DIR}"
    "${SAM_NODE}" run \
        --data-dir "${NODE_DIR}" \
        --control-plane "$CONTROL_PLANE" \
        --bootstrap-token-path "${BOOTSTRAP_TOKEN_PATH}" \
        --bind-addr "" \
        --socket-path "${NODE_UDS}" \
        > "${LOG_DIR}/sam-node.log" 2>&1 &

    # The boundaries are useless before the node answers, and starting a
    # thousand of them against a socket that does not exist yet produces a
    # thousand identical failures instead of one clear one.
    for _ in $(seq 1 600); do
        [ -S "${NODE_UDS}" ] && break
        sleep 0.1
    done
    [ -S "${NODE_UDS}" ] || {
        echo "node never bound ${NODE_UDS}" >&2
        tail -20 "${LOG_DIR}/sam-node.log" >&2
        exit 1
    }

    # A socket is not enrolment. A node with no identity serves a reduced
    # surface for enrolment and nothing else, so it binds the socket and then
    # waits forever -- which looks like success from here. /metrics exists only
    # on the full sidecar, so it is the cheapest honest proof of enrolment.
    enrolled=0
    for _ in $(seq 1 300); do
        code="$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "${NODE_UDS}" \
            http://localhost/metrics 2>/dev/null || true)"
        if [ "${code}" = "200" ]; then enrolled=1; break; fi
        sleep 1
    done
    [ "${enrolled}" -eq 1 ] || {
        echo "node bound its socket but never enrolled; is the bootstrap token valid?" >&2
        tail -20 "${LOG_DIR}/sam-node.log" >&2
        exit 1
    }
    echo "Node ready at ${NODE_UDS}"
fi

fc_put() {
    curl -sf -X PUT --unix-socket "$1" \
        "http://localhost$2" -H 'Content-Type: application/json' -d "$3" > /dev/null
}

# When each sandbox was launched, so a run can say how long a population took
# to come up rather than only that it did. Readiness is not recorded here: a
# sandbox is useful when its agent reaches the mesh, and only the node knows
# that. Pair this with the agent count over time from collect-fleet.sh.
TIMINGS="${LOG_DIR}/launch-timings.csv"
echo "index,launched_epoch_ms" > "${TIMINGS}"

echo "=== Launching $COUNT agent sandboxes ==="
for i in $(seq 1 "$COUNT"); do
    VM_ID="vm-$i"
    # Firecracker's vsock multiplexes guest connections onto
    # "<uds_path>_<port>", so the boundary must listen on that exact name for
    # the guest's connections to CID 2 port 1080 to arrive.
    VSOCK_UDS="${RUN_DIR}/sam-$VM_ID.vsock"
    BOUNDARY_UDS="${VSOCK_UDS}_1080"
    API_SOCKET="/tmp/firecracker-$VM_ID.socket"
    BUNDLE="${RUN_DIR}/sam-$VM_ID.bundle.yaml"

    rm -f "$VSOCK_UDS" "$BOUNDARY_UDS" "$API_SOCKET"

    # Each sandbox is a different agent, because a thousand sandboxes sharing
    # one identity would tell the mesh it is serving one agent very hard. The
    # identifier is dot-separated so one rule can match the whole population:
    # *.scale.sam-mesh.dev admits these and nothing else.
    #
    # An empty egress allowance is the interesting default: these agents reach
    # the mesh and nothing else, so anything they get to is something policy
    # granted.
    cat > "$BUNDLE" <<EOF
version: v1
agent:
  id: agent-${i}.${AGENT_DOMAIN}
egress:
  allow: []
EOF

    # There is no credential issuer in this harness, and the flag says so
    # rather than a default quietly meaning it.
    "${SAM_BOX}" run \
        --socket "$BOUNDARY_UDS" \
        --sidecar-socket "${NODE_UDS}" \
        --bundle "$BUNDLE" \
        --insecure-unverified-bundle \
        > "${LOG_DIR}/sam-box-$VM_ID.log" 2>&1 &

    firecracker --api-sock "$API_SOCKET" > "${LOG_DIR}/fc-$VM_ID.log" 2>&1 &

    for _ in $(seq 1 100); do
        [ -S "$API_SOCKET" ] && break
        sleep 0.05
    done

    # The kernel passes cmdline KEY=VALUE pairs it does not recognise to init
    # as environment variables, which is the only way to tell PID 1 anything:
    # it is started with an empty environment.
    fc_put "$API_SOCKET" /boot-source "{
        \"kernel_image_path\": \"$WORKDIR/vmlinux.bin\",
        \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off ro SANDBOX_LINGER=${SANDBOX_LINGER}${AGENT_ENV}\"
    }"

    fc_put "$API_SOCKET" /machine-config "{
        \"vcpu_count\": $VM_VCPUS,
        \"mem_size_mib\": $VM_MEM_MIB
    }"

    # One rootfs, shared read-only by every sandbox. A private copy per agent
    # is 500 MB of disk and a 500 MB write before the guest can even boot,
    # which at a thousand agents exhausts the disk long before the memory. The
    # guest gives itself tmpfs for the few paths that must be writable.
    fc_put "$API_SOCKET" /drives/rootfs "{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"$WORKDIR/rootfs.ext4\",
        \"is_root_device\": true,
        \"is_read_only\": true
    }"

    # Guest CID 3 is the first available guest CID. Connections the guest makes
    # to CID 2 surface on the host as "<uds_path>_<port>".
    fc_put "$API_SOCKET" /vsock "{
        \"vsock_id\": \"vsock0\",
        \"guest_cid\": 3,
        \"uds_path\": \"$VSOCK_UDS\"
    }"

    fc_put "$API_SOCKET" /actions '{ "action_type": "InstanceStart" }'

    echo "$i,$(date +%s%3N)" >> "${TIMINGS}"
    echo "Started $VM_ID as agent-${i}.${AGENT_DOMAIN} (${VM_VCPUS} vCPU, ${VM_MEM_MIB} MiB)"
done

echo "=== $COUNT sandboxes running against one node ==="
echo "How many agents the node thinks it is serving:"
echo "  grep sam_node_agents_seen <(curl -s --unix-socket $NODE_UDS http://localhost/metrics)"
