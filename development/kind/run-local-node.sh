#!/usr/bin/env bash
# Enroll a locally-built ./bin/sam-node into the kind mesh hub for local testing.
# The hub (exposed via sam-hub-nodeport + kind extraPortMappings) is reached at
# 127.0.0.1:9090 (HTTP enroll) and 127.0.0.1:4001 (libp2p TCP); the node relays
# peer traffic through the hub. Extra args pass through, e.g. to host a service:
#   ARGS="--config development/examples/calc-mcp/sam-node-config.yaml"
set -euo pipefail

CLUSTER="sam-kind"
NAMESPACE="sam-kind"
KCTX="kind-${CLUSTER}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${PROJECT_ROOT}"

# Prereqs
for bin in kubectl kind; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing prerequisite: $bin" >&2; exit 1; }
done
kind get clusters 2>/dev/null | grep -qx "${CLUSTER}" || {
  echo "kind cluster '${CLUSTER}' not found; start it first: make kind" >&2; exit 1; }
[[ -x ./bin/sam-node ]] || { echo "./bin/sam-node not found; build it first: make build" >&2; exit 1; }

# Identity + token
kubectl --context "${KCTX}" -n "${NAMESPACE}" create serviceaccount local-node-sa \
  >/dev/null 2>&1 || true
JWT="$(kubectl --context "${KCTX}" -n "${NAMESPACE}" create token local-node-sa \
  --audience=sam-mesh-audience --duration=1h)"

echo "Enrolling local ./bin/sam-node into mesh hub at http://127.0.0.1:9090…"
echo "  MCP/sidecar API on 127.0.0.1:9099"
exec ./bin/sam-node run \
  --hub http://127.0.0.1:9090 \
  --jwt "${JWT}" \
  --listen /ip4/0.0.0.0/tcp/0 \
  --bind-addr 127.0.0.1:9099 \
  --api-token devtoken \
  --discovery-interval 200ms \
  "$@"
