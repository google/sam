#!/usr/bin/env bash
# Enroll a locally-built ./bin/sam-node into the kind mesh the way a real external node joins:
# a bootstrap token over the control plane's gateway address, peer traffic through the router's
# node-IP multiaddrs. Extra args pass through, e.g. to host a service:
#   ARGS="--config development/examples/calc-mcp/sam-node-config.yaml"
set -euo pipefail

CLUSTER="sam-kind"
NAMESPACE="sam-kind"
KCTX="kind-${CLUSTER}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${PROJECT_ROOT}"

# Prereqs
for bin in kubectl kind curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing prerequisite: $bin" >&2; exit 1; }
done
kind get clusters 2>/dev/null | grep -qx "${CLUSTER}" || {
  echo "kind cluster '${CLUSTER}' not found; start it first: make kind-up" >&2; exit 1; }
[[ -x ./bin/sam-node ]] || { echo "./bin/sam-node not found; build it first: make build" >&2; exit 1; }

MAIN_IP="$(kubectl --context "${KCTX}" -n "${NAMESPACE}" get gateway sam-mesh-gateway \
  -o jsonpath='{.status.addresses[0].value}' 2>/dev/null || true)"
[[ -n "${MAIN_IP}" ]] || {
  echo "gateway 'sam-mesh-gateway' has no LoadBalancer address; is cloud-provider-kind running?" >&2
  exit 1; }
CONTROL_PLANE_URL="http://${MAIN_IP}"

# Mint an enrollment credential the way an operator would, through the dev-routed /admin API.
ADMIN_TOKEN="$(kubectl --context "${KCTX}" -n "${NAMESPACE}" get secret sam-mesh-secrets \
  -o jsonpath='{.data.admin-token}' | base64 -d)"
TOKEN_RESPONSE="$(curl -s -X POST "${CONTROL_PLANE_URL}/admin/bootstrap-tokens" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"role":"sam:role:node","ttl_hours":1,"max_usages":1,"description":"local sam-node"}' || true)"
BOOTSTRAP_TOKEN="$(printf '%s' "${TOKEN_RESPONSE}" | jq -r '.token // empty' 2>/dev/null || true)"
[[ -n "${BOOTSTRAP_TOKEN}" ]] || {
  echo "could not mint a bootstrap token at ${CONTROL_PLANE_URL}/admin/bootstrap-tokens: ${TOKEN_RESPONSE}" >&2
  exit 1; }

echo "Enrolling local ./bin/sam-node into the mesh control plane at ${CONTROL_PLANE_URL}…"
echo "  MCP/sidecar API on 127.0.0.1:9099"
export SAM_API_TOKEN=devtoken
exec ./bin/sam-node run \
  --control-plane "${CONTROL_PLANE_URL}" \
  --bootstrap-token "${BOOTSTRAP_TOKEN}" \
  --listen /ip4/0.0.0.0/tcp/0 \
  --bind-addr 127.0.0.1:9099 \
  --discovery-interval 200ms \
  --router-connect-timeout 10s \
  "$@"
