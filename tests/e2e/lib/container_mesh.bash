#!/usr/bin/env bash

# Shared BATS helpers for containerized SAM mesh tests.
# Refactored to use Kind-hosted unified OIDC and Hub services.

if [[ -z "${MESH_HELPERS_LOADED:-}" ]]; then
  MESH_HELPERS_LOADED=1

  MESH_RUNTIME_IMAGE="${MESH_RUNTIME_IMAGE:-sam-e2e-runtime:local}"
  MESH_NETWORK="kind"
  MESH_CONTAINERS=()
  MESH_PREFIX=""
  MESH_SOCKET_DIR=""

  mesh_cleanup_stale_resources() {
    local stale_containers
    stale_containers=$(docker ps -aq --filter "name=mesh-")
    if [[ -n "${stale_containers}" ]]; then
      docker rm -f ${stale_containers} >/dev/null 2>&1 || true
    fi
  }

  mesh_require_docker() {
    command -v docker >/dev/null 2>&1 || return 1
    docker info >/dev/null 2>&1 || return 1
    return 0
  }

  mesh_build_runtime_image() {
    if ! docker image inspect "${MESH_RUNTIME_IMAGE}" >/dev/null 2>&1; then
      docker build \
        -f tests/e2e/docker/Dockerfile.sam-runtime \
        -t "${MESH_RUNTIME_IMAGE}" \
        . >/dev/null
    fi
  }

  mesh_setup_env() {
    if [[ -n "${MESH_PREFIX:-}" ]]; then
      return 0
    fi
    mesh_build_runtime_image

    MESH_PREFIX="mesh-${BATS_TEST_NUMBER}-$$-$(date +%s)"
    MESH_SOCKET_DIR="/tmp/${MESH_PREFIX}-sockets"
    mkdir -p "${MESH_SOCKET_DIR}"
    CLEANUP_VOLUMES=()
  }

  mesh_cleanup_test_resources() {
    if [[ "${BATS_TEST_COMPLETED:-0}" -ne 1 ]]; then
      mkdir -p tests/e2e/logs
      local c
      for c in "${MESH_CONTAINERS[@]}"; do
        docker logs "${c}" > "tests/e2e/logs/${c}.log" 2>&1 || true
      done
    fi

    local c
    for c in "${MESH_CONTAINERS[@]}"; do
      docker rm -f "${c}" >/dev/null 2>&1 || true
    done
    MESH_CONTAINERS=()

    local v
    for v in "${CLEANUP_VOLUMES[@]}"; do
      docker volume rm "${v}" >/dev/null 2>&1 || true
    done
    CLEANUP_VOLUMES=()
  }

  mesh_cleanup_env() {
    mesh_cleanup_test_resources
  }

  mesh_gen_hex32() {
    hexdump -vn 32 -e '1/1 "%02x"' /dev/urandom
  }

  mesh_wait_for_log() {
    local container="$1"
    local needle="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s*10; i++)); do
      if docker logs "${container}" 2>&1 | grep -Fq "${needle}"; then
        return 0
      fi
      sleep 0.1
    done
    return 1
  }

  mesh_wait_for_mcp_ready() {
    local idx="$1"
    local timeout_s="${2:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      if docker run --rm --network "${MESH_NETWORK}" python:3.12 curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer secret-token" -d '{"jsonrpc":"2.0","method":"ping","id":1}' --max-time 5 -D - http://${MESH_PREFIX}-node-${idx}:8080/mcp | grep -q "200 OK"; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_get_node_count_via_mcp() {
    local idx="$1"
    local output
    output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://${MESH_PREFIX}-node-${idx}:8080/mcp" -tool "get_mesh_info" 2>/dev/null)"
    echo "${output}" | jq 'if .connected_peers then (.connected_peers | length) - 1 else 0 end'
  }

  mesh_wait_for_node_count() {
    local idx="$1"
    local expected="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      local output
      output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://${MESH_PREFIX}-node-${idx}:8080/mcp" -tool "get_mesh_info" 2>/dev/null)"
      echo "Node ${idx} get_mesh_info raw output: ${output}"
      local count
      count="$(echo "${output}" | jq 'if .connected_peers then (.connected_peers | length) - 1 else 0 end')"
      echo "Node ${idx} reported known peers count: ${count}"
      if [[ "${count}" -eq "${expected}" ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_wait_for_peer_connection() {
    local idx="$1"
    local target_peer="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      local output
      output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://${MESH_PREFIX}-node-${idx}:8080/mcp" -tool "get_mesh_info" 2>/dev/null)"
      echo "[$(date +%T)] Node ${idx} get_mesh_info raw output: ${output}"
      local connected
      connected="$(echo "${output}" | jq -r --arg peer "$target_peer" '.connected_peers | index($peer) != null')"
      echo "[$(date +%T)] Node ${idx} connection to ${target_peer}: ${connected}"
      if [[ "${connected}" == "true" ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  mesh_wait_for_peer_disconnection() {
    local idx="$1"
    local target_peer="$2"
    local timeout_s="${3:-20}"
    local i
    for ((i=0; i<timeout_s; i++)); do
      local output
      output="$(timeout 15s docker run --rm --network "${MESH_NETWORK}" "${MESH_RUNTIME_IMAGE}" mcp-client -url "http://${MESH_PREFIX}-node-${idx}:8080/mcp" -tool "get_mesh_info" 2>/dev/null)"
      echo "[$(date +%T)] Node ${idx} get_mesh_info raw output: ${output}"
      local connected
      connected="$(echo "${output}" | jq -r --arg peer "$target_peer" '.connected_peers | index($peer) != null')"
      echo "[$(date +%T)] Node ${idx} connection to ${target_peer}: ${connected}"
      if [[ "${connected}" == "false" ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }


  mesh_get_add_hosts() {
    local net="${MESH_NETWORK:-kind}"
    # Resolve mock-oidc node IP
    local oidc_node
    oidc_node=$(kubectl --context="${KUBECONTEXT:-kind-sam-wi-test}" get pod -l app=mock-oidc -o jsonpath='{.items[0].spec.nodeName}')
    local oidc_node_ip
    oidc_node_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "${oidc_node}")

    # Check if a custom local Hub container exists in this test scope
    local hub_ip=""
    local custom_hub="${MESH_PREFIX}-hub"
    if docker inspect "${custom_hub}" >/dev/null 2>&1; then
      hub_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "${custom_hub}")
      local cp_ip=""
      local custom_cp="${MESH_PREFIX}-hub-cp"
      if docker inspect "${custom_cp}" >/dev/null 2>&1; then
        cp_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "${custom_cp}")
      fi
      echo "--add-host mock-oidc:${oidc_node_ip} --add-host sam-hub:${hub_ip} --add-host sam-control-plane:${cp_ip}"
    else
      # Resolve sam-router-0 node IP
      local router_node
      router_node=$(kubectl --context="${KUBECONTEXT:-kind-sam-wi-test}" get pod sam-router-0 -o jsonpath='{.spec.nodeName}')
      local router_node_ip
      router_node_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "${router_node}")
      echo "--add-host mock-oidc:${oidc_node_ip} --add-host sam-hub:${router_node_ip} --add-host sam-router:${router_node_ip} --add-host sam-control-plane:${router_node_ip} --add-host ${router_node}:${router_node_ip}"
    fi
  }

  mesh_setup_suite() {
    export PATH="${HOME}/go/bin:$PATH"
    mesh_cleanup_stale_resources
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
      echo "docker not available or daemon not running" >&2
      return 1
    fi
    if ! command -v kind >/dev/null 2>&1; then
      echo "kind not available" >&2
      return 1
    fi
    if ! command -v kubectl >/dev/null 2>&1; then
      echo "kubectl not available" >&2
      return 1
    fi
    if ! command -v jq >/dev/null 2>&1; then
      echo "jq not available" >&2
      return 1
    fi

    cd "${BATS_TEST_DIRNAME}/../.."
    make
    make docker-build

    if [[ ! -x "./bin/sam-node" || ! -x "./bin/sam-control-plane" || ! -x "./bin/sam-router" || ! -x "./bin/mcp-client" ]]; then
      echo "missing binaries; run: make build" >&2
      return 1
    fi

    export KUBERNETES_CLUSTER_NAME="sam-wi-test"
    export KUBECONTEXT="kind-${KUBERNETES_CLUSTER_NAME}"

    if ! kind get clusters | grep -q "^${KUBERNETES_CLUSTER_NAME}$"; then
      kind delete cluster --name "${KUBERNETES_CLUSTER_NAME}" >/dev/null 2>&1 || true
      kind create cluster --name "${KUBERNETES_CLUSTER_NAME}" --config=tests/e2e/fixtures/kind-cluster.yaml
    else
      kind export kubeconfig --name "${KUBERNETES_CLUSTER_NAME}"
    fi

    kind load docker-image sam-control-plane:local --name "${KUBERNETES_CLUSTER_NAME}"
    kind load docker-image sam-router:local --name "${KUBERNETES_CLUSTER_NAME}"
    kind load docker-image sam-node:local --name "${KUBERNETES_CLUSTER_NAME}"
    kind load docker-image sam-mock-oidc:local --name "${KUBERNETES_CLUSTER_NAME}"

    kubectl --context="${KUBECONTEXT}" apply -f tests/e2e/fixtures/mock-oidc.yaml
    kubectl --context="${KUBECONTEXT}" rollout status deployment/mock-oidc --timeout=60s

    local kube_issuer
    kube_issuer=$(kubectl --context="${KUBECONTEXT}" get --raw /.well-known/openid-configuration | jq -r .issuer)
    [[ -n "${kube_issuer}" ]]

    kubectl --context="${KUBECONTEXT}" apply -f tests/e2e/fixtures/allow-anonymous-oidc.yaml

    export ISSUERS="http://mock-oidc:18080,${kube_issuer}"

    local oidc_node
    oidc_node=$(kubectl --context="${KUBECONTEXT}" get pod -l app=mock-oidc -o jsonpath='{.items[0].spec.nodeName}')
    local oidc_node_ip
    oidc_node_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${MESH_NETWORK:-kind}\").IPAddress}}" "${oidc_node}")

    envsubst '$ISSUERS' < tests/e2e/fixtures/control-plane.yaml | kubectl --context="${KUBECONTEXT}" apply -f -
    kubectl --context="${KUBECONTEXT}" rollout status deployment/sam-db --timeout=60s
    kubectl --context="${KUBECONTEXT}" rollout status deployment/sam-control-plane --timeout=60s

    local policy_json='{
      "roles": [
        {
          "name": "sam:role:node",
          "allowed_services": [
            "mcp://calculator",
            "mcp://db-agent",
            "mcp://http-tool",
            "mcp://stdio-tool",
            "system://sam.catalog"
          ],
          "allowed_targets": ["*"]
        },
        {
          "name": "sam:role:router",
          "allowed_services": ["*"],
          "allowed_targets": ["*"]
        }
      ],
      "bindings": [
        {
          "role": "sam:role:node",
          "members": ["group:data-scientist", "group:users"]
        },
        {
          "role": "sam:role:router",
          "members": ["group:routers"]
        }
      ]
    }'

    kubectl --context="${KUBECONTEXT}" run seed-policy \
      --image=curlimages/curl:8.6.0 \
      --restart=Never \
      --overrides="{\"spec\": {\"activeDeadlineSeconds\": 30}}" \
      -- \
      curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer super-secret-admin-token" \
        -d "${policy_json}" \
        http://sam-control-plane:8080/policies

    kubectl --context="${KUBECONTEXT}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/seed-policy --timeout=15s
    kubectl --context="${KUBECONTEXT}" delete pod seed-policy --ignore-not-found

    # Create curl pod in background to request token
    kubectl --context="${KUBECONTEXT}" run curl-token-gen \
      --image=curlimages/curl:8.6.0 \
      --restart=Never \
      --overrides='{"spec": {"activeDeadlineSeconds": 30}}' \
      -- \
      curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer super-secret-admin-token" \
        -d '{"role": "sam:role:router", "max_usages": 999999}' \
        http://sam-control-plane:8080/admin/bootstrap-tokens

    if ! kubectl --context="${KUBECONTEXT}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/curl-token-gen --timeout=15s; then
      echo "ERROR: Token generation pod failed! Diagnostics:"
      kubectl --context="${KUBECONTEXT}" describe pod curl-token-gen || true
      kubectl --context="${KUBECONTEXT}" logs pod/curl-token-gen || true
      kubectl --context="${KUBECONTEXT}" delete pod curl-token-gen --ignore-not-found || true
      exit 1
    fi

    local token_json
    token_json=$(kubectl --context="${KUBECONTEXT}" logs pod/curl-token-gen)
    kubectl --context="${KUBECONTEXT}" delete pod curl-token-gen --ignore-not-found

    local router_token
    router_token=$(echo "${token_json}" | jq -r .token)
    [[ -n "${router_token}" && "${router_token}" != "null" ]]

    kubectl --context="${KUBECONTEXT}" create secret generic sam-router-token --from-literal=token="${router_token}" --dry-run=client -o yaml | kubectl --context="${KUBECONTEXT}" apply -f -

    kubectl --context="${KUBECONTEXT}" apply -f tests/e2e/fixtures/router.yaml
    kubectl --context="${KUBECONTEXT}" rollout status statefulset/sam-router --timeout=60s

    local i
    for ((i=0; i<200; i++)); do
      if kubectl --context="${KUBECONTEXT}" logs "sam-router-0" 2>&1 | grep -q "PeerID:"; then
        break
      fi
      sleep 0.1
    done
    local hub_peer_id
    hub_peer_id=$(kubectl --context="${KUBECONTEXT}" logs "sam-router-0" | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1 || true)
    [[ -n "${hub_peer_id}" ]]

    echo "${hub_peer_id}" > "/tmp/sam-wi-test-hub-peer-id"
    return 0
  }

  mesh_teardown_suite() {
    cd "${BATS_TEST_DIRNAME}/../.."
    mesh_cleanup_stale_resources
    # kind delete cluster --name "${KUBERNETES_CLUSTER_NAME:-sam-wi-test}" >/dev/null 2>&1 || true
    echo "teardown suite"
  }

  mesh_start_node() {
    local idx="$1"
    local flags="${2:-}"
    local config_path="${3:-}"
    local name="${MESH_PREFIX}-node-${idx}"

    local add_hosts
    add_hosts=$(mesh_get_add_hosts)

    local hub_peer_id
    hub_peer_id=$(cat "/tmp/${MESH_PREFIX}-hub-peer-id")

    local mount_args=()
    local config_args=()
    if [[ -n "${config_path}" ]]; then
      local abs_config
      abs_config=$(realpath "${config_path}")
      mount_args+=(-v "${abs_config}:/etc/sam/node-config.yaml:ro")
      config_args+=(--config /etc/sam/node-config.yaml)
    fi

    docker run -d \
      --name "${name}" \
      --network "${MESH_NETWORK}" \
      --network-alias "${name}" \
      ${add_hosts} \
      "${mount_args[@]}" \
      "${MESH_RUNTIME_IMAGE}" \
      /usr/local/bin/sam-node run \
      ${flags} \
      --log-level debug \
      --discovery-interval 2s \
      --hub "http://sam-control-plane:8080" \
      --client-id "sam-mesh-audience" \
      --client-secret "sam-e2e-secret" \
      --oidc-issuer "http://mock-oidc:18080" \
      --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
      --listen "/ip4/0.0.0.0/tcp/5002" \
      --bind-addr "0.0.0.0:8080" \
      --api-token "secret-token" \
      --mesh "${MESH_PREFIX}" \
      --dht-provider-addr-ttl 5s \
      --dht-max-record-age 5s \
      "${config_args[@]}" >/dev/null

    MESH_CONTAINERS+=("${name}")
  }

  mesh_start_mock_oidc() {
    # No-op: Mock OIDC is running in k8s
    return 0
  }

  mesh_start_hub() {
    # No-op: Hub is running in k8s
    local peer_id
    peer_id=$(cat "/tmp/sam-wi-test-hub-peer-id")
    echo "${peer_id}" > "/tmp/${MESH_PREFIX}-hub-peer-id"
    return 0
  }

  mesh_assert_container_running() {
    local name="$1"
    if [[ "${name}" == *"-hub" ]]; then
      kubectl --context="${KUBECONTEXT:-kind-sam-wi-test}" get pod sam-router-0 -o jsonpath='{.status.phase}' | grep -q "Running"
      return $?
    fi
    local state
    state="$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)"
    [[ "${state}" == "true" ]]
  }
fi
