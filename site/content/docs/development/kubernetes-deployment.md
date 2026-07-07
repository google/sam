---
title: "Kubernetes Deployment and Local Testing Guide"
linkTitle: "Kubernetes Deployment and Local Testing Guide"
---
This guide explains how to deploy the `sam-hub` in a Kubernetes cluster and how to test it locally with `kind` — using the bundled `make kind-*` targets for a one-command mesh, or a manual setup with `cloud-provider-kind`.

> [!TIP]
> This guide focuses on local development sandboxing. For production-grade Kubernetes deployments (GKE, EKS, AKS), see the [Production Kubernetes Deployment](../../user/kubernetes-deployment/) guide.

---

## 1. Local Testing with Kind

The repository ships a one-command local mesh under `development/kind/`, driven by `make` targets. This is the fastest way to get a running hub and a few nodes on your machine.

### Automated Mesh (Recommended)

```bash
make kind-up
```

This creates a `sam-kind` cluster (one control-plane plus workers for the hub and `node-a`, `node-b`, `node-c`), builds the `sam-hub:local` and `sam-node:local` images, loads them into the cluster, and deploys:

- The **hub**, configured to trust the cluster's own OIDC issuer.
- Three **nodes** declared in `development/kind/mesh-config.yaml`: `node-a` (bare), `node-b` (hosts the `calc-mcp` example service), and `node-c` (hosts the `greeter-mcp` example service).

Nodes authenticate to the hub via **Workload Identity Federation** (projected ServiceAccount tokens), so no static secrets or mock OIDC provider are needed. The hub is exposed to the host on `127.0.0.1:9090` (HTTP enroll) and `127.0.0.1:4001` (libp2p) via a NodePort and the cluster's `extraPortMappings` — `cloud-provider-kind` is not required.

Once everything is up, `make kind-up` opens a tmux session with live per-pod logs (hub and each node in its own pane). Manage the mesh with:

```bash
make kind-up ARGS=-s     # bring the mesh up without attaching the log view
make kind-logs           # (re)attach the live-logs tmux session
make kind-down           # delete the sam-kind cluster
```

### Mesh Layout (`mesh-config.yaml`)

The nodes that make up the dev mesh are declared in `development/kind/mesh-config.yaml`. Each entry maps a node to an optional service:

```yaml
# node -> service. A blank value means a bare node (no service, e.g. a caller).
# The service value is a folder name under development/examples/.
node-a:
node-b: calc-mcp
node-c: greeter-mcp
```

- The key is the node's name. The cluster currently ships with a hub plus these **three** agent nodes; each is pinned to a matching worker via the `sam-role` labels in `kind-config.yaml`.
- A **blank** value is a bare node — a `sam-node` with no local service, useful as a caller/consumer.
- A **non-blank** value is a folder name under `development/examples/`. That service is built and deployed as a **sidecar** next to the node, and the node is configured to advertise it to the mesh.

When a node has a service, `make kind-up` builds the service image from its `Dockerfile`, loads it into the cluster, and mounts the service's `sam-node-config.yaml` into the node. Because `make kind-up` only runs against a fresh cluster (it refuses if `sam-kind` already exists), **services are (re)deployed on cluster recreation** — after editing `mesh-config.yaml` or a service, run `make kind-down && make kind-up` to pick up the change.

### Adding and Testing a New Service

A service is any backend a node advertises to the mesh. Its kind is set by the `type` field in `sam-node-config.yaml`. SAM currently supports `mcp` (an MCP server) and `inference` (an LLM inference endpoint). The repository ships example MCP services under `development/examples/` (`calc-mcp`, `greeter-mcp`, `code-reviewer-mcp`, and `everything-mcp`) which are the easiest starting point. Using `calc-mcp` as a template:

1. **Create the service folder** `development/examples/my-mcp/` with:
   - The service backend (e.g. `my_server.py`) listening on a local port, plus a `Dockerfile` and any `requirements.txt`.
   - A `sam-node-config.yaml` declaring the service. Set `type` to the service kind and point `target_url` at the backend's local port:
     ```yaml
     version: "v1alpha1"
     attenuation:
       policies:
     services:
       - type: "mcp"
         name: "my-service"
         description: "What it does"
         target_url: "http://127.0.0.1:7779/mcp"
     ```
     The sidecar and `sam-node` share the pod's network, so `target_url` is always `127.0.0.1:<port>`, where `<port>` matches the port your service listens on.

2. **Assign it to a node** in `mesh-config.yaml` — replace an existing mapping or use a free node slot (`node-a`, `node-b`, `node-c`):
   ```yaml
   node-a: my-mcp
   node-b: calc-mcp
   node-c: greeter-mcp
   ```
   > [!NOTE]
   > There are three node slots because `kind-config.yaml` defines three workers labeled `sam-role: node-a|node-b|node-c`. To host more than three services at once, add a matching labeled worker there too.

3. **Recreate the cluster** so the new service is built and deployed:
   ```bash
   make kind-down && make kind-up
   ```

4. **Discover and call it** from another node — enroll a local node and use the MCP client:
   ```bash
   make kind-local-node
   # in another shell:
   ./bin/mcp-client -url http://127.0.0.1:9099/mcp -token devtoken -tool find_remote_tools -args '{}'
   ```
   `find_remote_tools` lists the discovered tools (e.g. `mcp://my-service/...`) and the peer hosting them; pass that `peer_id` and `tool_name` to `call_remote_tool` to invoke it.

### Enrolling a Local Node

To iterate on `sam-node` without rebuilding the image, enroll a locally-built binary into the running mesh:

```bash
make build            # produce ./bin/sam-node
make kind-local-node
```

This mints a ServiceAccount token and runs `./bin/sam-node` against the hub at `127.0.0.1:9090`, exposing its MCP API on `127.0.0.1:9099` with the API token `devtoken`. Extra flags pass through via `ARGS`, e.g. to host an example service:

```bash
make kind-local-node ARGS="--config development/examples/calc-mcp/sam-node-config.yaml"
```

You can then drive it with the bundled MCP client:

```bash
./bin/mcp-client -url http://127.0.0.1:9099/mcp -token devtoken -tool find_remote_tools -args '{}'
```

### End-to-End Mesh Check

To verify the full discovery-and-call path against a freshly built mesh:

```bash
make kind-e2e-mesh
```

This enrolls a local node, waits for it to discover `mcp://calculator/add` (hosted by `node-b`), calls `add(2, 3)`, and asserts the result is `5`.

---

## 2. Manual Deployment

If you'd rather deploy the pieces by hand — for example to exercise the Mock OIDC provider or wire up Google OIDC — you can apply the manifests below to a cluster yourself. SAM supports either a **Mock OIDC Provider** (recommended for quick local testing, since it needs no external credentials) or **Google OIDC** for authentication. The local `kind` path below uses `cloud-provider-kind` to allocate LoadBalancer IPs.

### Mock OIDC Provider Manifests (Optional)

The manifests for the mock OIDC provider are available in [mock-oidc.yaml](manifests/mock-oidc.yaml).

[mock-oidc.yaml](manifests/mock-oidc.yaml ':include')

### SAM Hub Manifests

The manifests for the SAM Hub are available in [sam-hub.yaml](manifests/sam-hub.yaml).

[sam-hub.yaml](manifests/sam-hub.yaml ':include')

### Configuring Google OIDC (Optional)

To use Google as the OIDC provider instead of the mock provider:

2.  **No Redirect URI required:** Because `sam-node` implements RFC 8252 (dynamic loopback port selection for native apps), you don't need to configure a specific Redirect URI when setting up a Desktop app. The authorization server will automatically allow loopback redirects.
3.  **Update Secret:** Update the `sam-hub-secret` in `sam-hub.yaml` with your Google credentials:
    ```yaml
    SAM_OIDC_ISSUER: "https://accounts.google.com"
    SAM_OIDC_ID: "<your-client-id>.apps.googleusercontent.com"
    SAM_OIDC_SECRET: "<your-client-secret>"
    ```

### Deploying to Kind

#### Step 1: Create a Kind Cluster
```bash
kind create cluster --name sam-test
```

#### Step 2: Run cloud-provider-kind
Run it in a separate terminal:
```bash
cloud-provider-kind
```

#### Step 3: Load Images into Kind
```bash
kind load docker-image sam-hub:local --name sam-test
kind load docker-image sam-node:local --name sam-test
```

#### Step 4: Apply Manifests

If using the **Mock OIDC Provider**:
```bash
kubectl apply -f mock-oidc.yaml
kubectl apply -f sam-hub.yaml
```

If using **Google OIDC**:
```bash
kubectl apply -f sam-hub.yaml
```

#### Step 5: Get the External IP
You can use the following command to extract the allocated IP into an environment variable:

```bash
HUB_IP=$(kubectl get svc sam-hub -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

---

## 3. Connecting an Agent

To connect a `sam-node` to the hub, you just need the hub's external IP and port.

### Enrolling the Agent

To connect a `sam-node` to the hub for the first time, you need to enroll it. The node needs to authenticate with the hub using a JWT token.

If you are using the **Mock OIDC Provider**, the node can fetch the token using OIDC Client Credentials flow:

1. **Get the Mock OIDC Service IP:**
   ```bash
   MOCK_IP=$(kubectl get svc mock-oidc -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   ```

2. **Run the Node to enroll:**
   ```bash
   sam-node run \
     --hub "http://$HUB_IP:9090" \
     --oidc-issuer "http://$MOCK_IP:18080" \
     --client-id "sam-mesh-audience" \
     --client-secret "sam-e2e-secret"
   ```

If you are using **Google OIDC**, you must obtain a valid Google ID token for your user and pass it via the `--jwt` flag:
```bash
sam-node run \
  --hub "http://$HUB_IP:9090" \
  --jwt "<your-google-id-token>"
```

Once enrolled, the identity is stored in the local database (`agent.db`), and you can run subsequent times without OIDC credentials:
```bash
sam-node run
```

---

## 4. Automating Node Deployment

To automate the deployment of `sam-nodes` in Kubernetes and have them fetch the JWT token automatically, you can use a standard Kubernetes `Deployment` or `StatefulSet`.

### Example Deployment

Here is a sample manifest that uses the in-cluster DNS to fetch the token from the mock provider:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sam-node
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sam-node
  template:
    metadata:
      labels:
        app: sam-node
    spec:
      containers:
      - name: sam-node
        image: sam-node:local
        command: ["sam-node", "run"]
        args:
        - "--hub"
        - "http://sam-hub:9090"
        - "--oidc-issuer"
        - "http://mock-oidc:18080"
        - "--client-id"
        - "sam-mesh-audience"
        - "--client-secret"
        - "sam-e2e-secret"
        env:
        - name: HOME
          value: /data
        volumeMounts:
        - name: data-volume
          mountPath: /data
      volumes:
      - name: data-volume
        emptyDir: {}
```

### Supported Authentication Flows

The SAM project supports three primary flows for acquiring a JWT token to enroll nodes, depending on the environment and security requirements:

#### 1. Client Credentials Flow (Machine-to-Machine)
*   **Description:** Defined in OAuth 2.0 RFC 6749, section 4.4. An application exchanges its application credentials (such as Client ID and Client Secret) for an access token.
*   **Use Case:** For unattended services or deployments connecting to a production OIDC provider.
*   **How to use:** Pass the `--oidc-issuer`, `--client-id`, and `--client-secret` flags to `sam-node run`.
*   **Example:**
```bash
sam-node run \
  --hub "http://hub.example.com:9090" \
  --oidc-issuer "https://accounts.google.com" \
  --client-id "$SAM_OIDC_ID" \
  --client-secret "$SAM_OIDC_SECRET"
```

#### 2. Native App Authorization Code Flow (Human Intervention)
*   **Description:** For devices operated by humans, this uses the standard Authorization Code Flow with PKCE for native apps (RFC 8252). The human operator runs `sam-node join` to open a web browser (or get a verification code via `--headless`), completes the login, and obtains a Biscuit token which is stored in the local database (`agent.db`).
*   **Use Case:** When a human operator is enrolling a node manually via their local terminal.
*   **How to use:** Run `sam-node join <hub-url>` before running the node daemon. Alternatively, you can obtain a token yourself and pass it via the `--jwt` flag to `sam-node run`.
*   **Example:**
```bash
# First, join interactively:
sam-node join https://hub.example.com

# Then start the node daemon:
sam-node run
```

#### 3. Workload Identity Federation (Secretless Kubernetes)
*   **Description:** The current best practice in Kubernetes. It removes the need for static secrets entirely. The machine proves its identity based on where it is running by presenting a ServiceAccount token (a signed JWT issued by the K8s API).
*   **Use Case:** Production Kubernetes deployments.
*   **How it works:** The Pod has a ServiceAccount token mounted. The Pod presents this token to the `sam-hub`. The hub verifies it by calling back to the Kubernetes OIDC discovery endpoint.
*   **How to use:** Pass the path to the mounted ServiceAccount token to the `--jwt-path` flag.
*   **Example:**
```bash
sam-node run \
  --hub "http://hub.example.com:9090" \
  --jwt-path "/var/run/secrets/kubernetes.io/serviceaccount/token"
```
> [!NOTE]
> The `sam-hub` must be configured to trust the Kubernetes API server as an OIDC issuer for this flow to work.

---

## 5. Configuring Workload Identity in Kubernetes

Workload Identity allows `sam-node` pods to authenticate with the `sam-hub` using their Kubernetes ServiceAccount token, removing the need for static credentials.

Here are the exact steps to configure this:

### Step 1: Ensure OIDC Discovery is enabled on your Cluster
Most managed Kubernetes services (GKE, EKS, AKS) and local tools like `kind` support ServiceAccount Issuer Discovery.
In `kind`, this is enabled by default. You can find the issuer URL by running:
```bash
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
```
(Or check your cloud provider's documentation for the public issuer URL).

### Step 2: Configure the Hub to trust the Kubernetes Issuer
Update the `sam-hub` deployment to include the Kubernetes issuer URL in the `--issuer` flag.

If you are using `kind`, the issuer URL is usually `https://kubernetes.default.svc.cluster.local` (internal) or the external URL mapped by kind.

Update `sam-hub.yaml`:
```yaml
    spec:
      containers:
      - name: sam-hub
        args:
        - "--issuer"
        - "https://accounts.google.com,https://kubernetes.default.svc.cluster.local"
```

### Step 3: Create a ServiceAccount for the Node
Create a ServiceAccount that the `sam-node` pods will use.
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sam-node-sa
```

### Step 4: Deploy the Node with a Projected Volume
Deploy the `sam-node` and configure it to use the ServiceAccount. We use a **Projected Volume** to request a token with the specific audience expected by the hub (e.g., the mesh name or a specific client ID).

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sam-node
spec:
  replicas: 3
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
        command: ["sam-node", "run"]
        args:
        - "--hub"
        - "http://sam-hub:9090"
        - "--jwt-path"
        - "/var/run/secrets/tokens/sam-token"
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
              audience: "sam-hub-audience" # Match this with what the hub expects
```
