#!/usr/bin/env bats

setup() {
  if ! command -v kind >/dev/null 2>&1; then
    skip "kind not available"
  fi
  if ! command -v kubectl >/dev/null 2>&1; then
    skip "kubectl not available"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    skip "jq not available"
  fi

  # We use a unique cluster name to avoid conflicts
  CLUSTER_NAME="sam-wi-test-$RANDOM"
  
  # Create Kind cluster
  kind create cluster --name "${CLUSTER_NAME}"
  
  # Build images
  make docker-build
  
  # Load images into Kind
  kind load docker-image sam-hub:local --name "${CLUSTER_NAME}"
  kind load docker-image sam-node:local --name "${CLUSTER_NAME}"
}

teardown() {
  echo "=== Hub Logs ==="
  kubectl logs -l app=sam-hub --tail=-1 || true
  echo "=== Node Logs ==="
  kubectl logs -l app=sam-node --tail=-1 || true
  kind delete cluster --name "${CLUSTER_NAME}"
}

k8s_wait_for_log() {
  local pod="$1"
  local needle="$2"
  local timeout_s="${3:-20}"
  local i
  for ((i=0; i<timeout_s*10; i++)); do
    if kubectl logs "${pod}" 2>&1 | grep -q "${needle}"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

@test "Workload Identity Federation in Kind" {
  # 1. Get the issuer URL
  local issuer
  issuer=$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)
  [[ -n "${issuer}" ]]

  # 1.5. Grant anonymous access to OIDC discovery
  cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: oidc-reader
rules:
- nonResourceURLs:
  - /.well-known/openid-configuration
  - /openid/v1/jwks
  verbs:
  - get
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: allow-anonymous-oidc
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: oidc-reader
subjects:
- kind: User
  name: system:anonymous
  apiGroup: rbac.authorization.k8s.io
EOF

  # 2. Deploy Hub
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: sam-hub-config
data:
  SAM_OIDC_ISSUER: "${issuer}"
  SAM_OIDC_ID: "sam-mesh-audience"
  SAM_HUB_KEY: "0000000000000000000000000000000000000000000000000000000000000000"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sam-hub
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sam-hub
  template:
    metadata:
      labels:
        app: sam-hub
    spec:
      containers:
      - name: sam-hub
        image: sam-hub:local
        args:
        - "--issuer"
        - "${issuer}"
        - "--key"
        - "0000000000000000000000000000000000000000000000000000000000000000"
        - "--listen"
        - "/ip4/0.0.0.0/tcp/4002"
        - "--insecure-skip-tls-verify"
        envFrom:
        - configMapRef:
            name: sam-hub-config
---
apiVersion: v1
kind: Service
metadata:
  name: sam-hub
spec:
  type: ClusterIP
  ports:
  - name: p2p
    port: 4002
    targetPort: 4002
  - name: http
    port: 9090
    targetPort: 9090
  selector:
    app: sam-hub
EOF

  # Wait for Hub to be ready
  kubectl wait --for=condition=available deployment/sam-hub --timeout=60s

  # Get Hub Pod Name
  local hub_pod_name
  hub_pod_name=$(kubectl get pods -l app=sam-hub -o jsonpath='{.items[0].metadata.name}')
  
  # Wait for PeerID to appear in logs
  k8s_wait_for_log "${hub_pod_name}" "PeerID:" 20
  
  # Get Hub PeerID
  local hub_peer_id
  hub_peer_id=$(kubectl logs "${hub_pod_name}" | grep -oE '12D3Koo[a-zA-Z0-9]+' | head -n 1)
  
  [[ -n "${hub_peer_id}" ]]

  # 3. Deploy Node
  # Create ServiceAccount
  kubectl create serviceaccount sam-node-sa

  # Deploy Node with projected volume
  cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sam-node
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sam-node
  template:
    metadata:
      labels:
        app: sam-node
    spec:
      serviceAccountName: sam-node-sa
      containers:
      - name: sam-node
        image: sam-node:local
        command: ["/sam-node", "run"]
        args:
        - "--hub"
        - "http://sam-hub:9090"
        - "--jwt-path"
        - "/var/run/secrets/tokens/sam-token"
        - "--api-token"
        - "secret-token"
        volumeMounts:
        - name: sam-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
      volumes:
      - name: sam-token
        projected:
          sources:
          - serviceAccountToken:
              path: sam-token
              expirationSeconds: 3600
              audience: "sam-mesh-audience"
EOF

  # Wait for Node to be ready
  kubectl wait --for=condition=available deployment/sam-node --timeout=60s

  # 4. Verify enrollment by checking logs
  local pod_name
  pod_name=$(kubectl get pods -l app=sam-node -o jsonpath='{.items[0].metadata.name}')
  
  # Wait a bit for enrollment to happen
  sleep 10
  
  local logs
  logs=$(kubectl logs "${pod_name}")
  
  [[ "$logs" == *"SAM Node Online"* ]] || [[ "$logs" == *"Successfully enrolled"* ]]
}
