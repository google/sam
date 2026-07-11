---
title: "Production Kubernetes Deployment"
linkTitle: "Kubernetes Deployment"
weight: 30
---

This guide explains how to deploy a production-grade SAM cluster (Hub, DNS synchronizer, OIDC bridge, and Nodes) in a Kubernetes environment (like GKE, EKS, AKS, or custom bare-metal clusters), based on our official public testnet architectures.

---

## 1. Architecture Overview

A production SAM deployment consists of:
*   **Dex (OIDC Provider)**: Serves as the identity bridge, federation point, and login broker.
*   **SAM Control Plane (`sam-control-plane`)**: Runs as a stateless **Deployment** to verify OIDC tokens and issue capabilities (Biscuits) based on identity policies.
*   **SAM Router (`sam-router`)**: Runs as a **StatefulSet** to maintain stable network identity. P2P nodes use these bootstrap routers to connect to the GossipSub mesh overlay.
*   **DNS Sync CronJob**: Dynamically queries the `sam-router` StatefulSet pod IP addresses and updates DNS A/AAAA records for P2P bootstrap resolution.
*   **SAM Nodes (`sam-node`)**: Deployed as containerized gateways that authenticate securely to the control plane using Kubernetes Workload Identity (ServiceAccount token projection).

```mermaid
graph TD
    User([User / Client]) -->|HTTPS / OIDC| Dex[Dex Identity Bridge]
    Node[sam-node Gateway Pod] -->|HTTPS Enroll| CP[sam-control-plane Deployment]
    Router[sam-router StatefulSet] -->|HTTPS Enroll| CP
    Node -->|P2P Mesh Overlay| Router
    CP -->|OIDC Discovery Check| Dex
    Cron[DNS Sync CronJob] -->|Poll Pod IPs| K8sApi[Kubernetes API]
    Cron -->|Update A Records| CloudDNS[Cloud DNS / DNS Registry]
    Node -->|Bootstrap DNS Resolution| CloudDNS
```

---

## 2. Step 1: Deploying the OIDC Provider (Dex)

Dex maps external accounts (Google, GitHub, LDAP) to standard OIDC identities in the cluster.

### 1. Provision Dex Secrets
Idempotently create the secret containing your OAuth client applications' credentials:
```bash
kubectl create secret generic dex-secrets \
  --namespace=dex \
  --from-literal=google-client-id="<my-google-client-id>" \
  --from-literal=google-client-secret="<my-google-client-secret>" \
  --from-literal=github-client-id="<my-github-client-id>" \
  --from-literal=github-client-secret="<my-github-client-secret>" \
  --from-literal=cli-oauth-secret="<my-ephemeral-cli-oauth-secret>" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 2. Apply Dex Manifests
Deploy the Dex deployment and configuration mapping:
```yaml
# dex-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dex-config
  namespace: dex
data:
  config.yaml: |
    issuer: https://AUTH.YOUR-DOMAIN.COM
    storage:
      type: kubernetes
      config:
        inCluster: true
    web:
      http: 0.0.0.0:5556
    connectors:
      - type: google
        id: google
        name: Google
        config:
          clientID: $GOOGLE_CLIENT_ID
          clientSecret: $GOOGLE_CLIENT_SECRET
          redirectURI: https://AUTH.YOUR-DOMAIN.COM/callback
    staticClients:
      - id: YOUR-CLI-AUDIENCE
        name: 'SAM Mesh native client'
        secret: $CLI_OAUTH_SECRET
        redirectURIs:
          - 'urn:ietf:wg:oauth:2.0:oob'
          - 'http://localhost:8000'
```
Deploy the deployment manifests located in the repository's `.github/k8s/dex-deployment.yaml` and wait for readiness:
```bash
kubectl rollout status deployment/dex -n dex
```

---

## 3. Step 2: Deploying SAM Control Plane and Router

The Control Plane verifies OIDC tokens and manages access policies. The Routers handle peer discovery and routing within the GossipSub mesh.

### 1. Configure Access Control Policies (`policies.yaml`)
Create a ConfigMap defining your global mesh access rules:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sam-control-plane-policies
  namespace: sam
data:
  policies.yaml: |
    version: "v1alpha1"
    bindings:
      - members: ["user:system:serviceaccount:sam-nodes:sam-node-sa"]
        role: "node-role"
    roles:
      node-role:
        allowed_services:
          - "*"
        allowed_targets:
          - "*"
```
```bash
kubectl apply -f policies-configmap.yaml
```

### 2. Deploy SAM Control Plane
The Control Plane is stateless and can scale horizontally. It connects to a shared PostgreSQL database to persist active leases and rotated capability signing keys.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sam-control-plane
  namespace: sam
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sam-control-plane
  template:
    metadata:
      labels:
        app: sam-control-plane
    spec:
      containers:
      - name: sam-control-plane
        image: ghcr.io/google/sam-control-plane:latest
        args:
        - "--bind-address=0.0.0.0:8080"
        - "--db-driver=postgres"
        - "--db-dsn=postgres://sam:password@sam-db-service:5432/sam_mesh?sslmode=disable"
        - "--issuer=https://AUTH.YOUR-DOMAIN.COM"
        - "--allowed-audiences=YOUR-CLIENT-AUDIENCE"
        - "--policy-file=/etc/sam/policies/policies.yaml"
        ports:
        - containerPort: 8080
          name: http
        volumeMounts:
        - name: policies-volume
          mountPath: /etc/sam/policies
          readOnly: true
      volumes:
      - name: policies-volume
        configMap:
          name: sam-control-plane-policies
```

### 3. Deploy SAM Router StatefulSet
The Router must be deployed as a StatefulSet to allocate a persistent volume for storing its libp2p identity key, ensuring a stable Peer ID across pod restarts.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sam-router-sa
  namespace: sam
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: sam-router
  namespace: sam
spec:
  serviceName: "sam-router"
  replicas: 3
  selector:
    matchLabels:
      app: sam-router
  template:
    metadata:
      labels:
        app: sam-router
    spec:
      serviceAccountName: sam-router-sa
      containers:
      - name: sam-router
        image: ghcr.io/google/sam-router:latest
        ports:
        - containerPort: 4501
          protocol: TCP
          name: p2p-tcp
        - containerPort: 4501
          protocol: UDP
          name: p2p-udp
        args:
        - "--control-plane=http://sam-control-plane.sam.svc.cluster.local:8080"
        - "--listen=/ip4/0.0.0.0/tcp/4501"
        - "--listen=/ip4/0.0.0.0/udp/4501/quic-v1"
        - "--jwt-path=/var/run/secrets/tokens/sam-token"
        - "--keys-path=/data/router.key"
        volumeMounts:
        - name: sam-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
        - name: router-data
          mountPath: /data
      volumes:
      - name: sam-token
        projected:
          sources:
          - serviceAccountToken:
              path: sam-token
              expirationSeconds: 3600
              audience: "sam-hub-audience"
  volumeClaimTemplates:
  - metadata:
      name: router-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 1Gi
```

---

## 4. Step 3: DNS Synchronization (DHT Bootstrapping)

In a decentralized DHT network, nodes need stable DNS multiaddrs (`/dnsaddr/BOOTSTRAP.YOUR-DOMAIN.COM`) to resolve bootstrap peers. Since Kubernetes StatefulSet pod IP addresses change on restart, you must deploy a sync cronjob that updates A/AAAA records on your DNS provider.

### DNS Sync CronJob Example
The sync script:
1. Queries the Kubernetes API for the external/internal IP addresses of the `sam-router` pods.
2. Updates your Cloud DNS zone (e.g. Google Cloud DNS, AWS Route53) dynamically.
3. Announce new multiaddrs via TXT records.

Refer to [dns-sync-cronjob-template.yaml](https://github.com/google/sam/blob/main/.github/k8s/dns-sync-cronjob-template.yaml) for our official Cloud DNS sync cronjob.

---

## 5. Step 4: Deploying SAM Nodes (Workload Identity)

To secure nodes without distributing static passwords, configure nodes to authenticate via **ServiceAccount projected tokens** (Workload Identity Federation).

### 1. Create a ServiceAccount
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sam-node-sa
  namespace: sam-nodes
```

### 2. Configure Node Identity and Services
Create a ConfigMap defining the node's local services and local security target identity (see the [Node Configuration Guide](../node-configuration/) for schema details):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sam-node-config
  namespace: sam-nodes
data:
  sam-node.yaml: |
    version: "v1alpha1"
    services:
      - type: mcp
        name: db-agent
        command: ["echo", "placeholder db-agent service"]
    attenuation:
      rules:
        - 'department("analytics") <- true;'
      policies:
        - 'deny if user("untrusted_user");'
```

### 3. Deploy Nodes using Token Projection
Deploy the nodes. We use a `projected` volume to request a short-lived token containing the audience expected by the control plane (`sam-hub-audience`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sam-node
  namespace: sam-nodes
spec:
  replicas: 5
  template:
    spec:
      serviceAccountName: sam-node-sa
      containers:
      - name: sam-node
        image: ghcr.io/google/sam-node:latest
        args: 
          - "run"
          - "--config=/etc/sam/sam-node.yaml"
          - "--hub=http://sam-control-plane.sam.svc.cluster.local:8080"
          - "--jwt-path=/var/run/secrets/tokens/sam-token"
          - "--api-token=secret-token"
        volumeMounts:
        - name: config-volume
          mountPath: /etc/sam
        - name: sam-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
      volumes:
      - name: config-volume
        configMap:
          name: sam-node-config
      - name: sam-token
        projected:
          sources:
          - serviceAccountToken:
              path: sam-token
              expirationSeconds: 3600
              audience: "sam-hub-audience" # Match this with what the control plane expects
```

---

## 6. Local Sandbox Testing (Kind)

If you are looking to test Kubernetes deployments locally in a sandboxed cluster without external cloud dependencies, please follow the [Local Kubernetes Testing Guide](../../development/kubernetes-deployment/).
