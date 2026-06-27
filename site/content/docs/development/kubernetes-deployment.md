---
title: "Kubernetes Deployment and Local Testing Guide"
linkTitle: "Kubernetes Deployment and Local Testing Guide"
---
This guide explains how to deploy the `sam-hub` in a Kubernetes cluster and how to test it locally using `kind` and `cloud-provider-kind`.

This guide supports using either **Google OIDC** or a **Mock OIDC Provider** for authentication. The mock provider is recommended for quick local testing as it does not require creating external credentials.

---

## 1. Mock OIDC Provider Manifests (Optional)

The manifests for the mock OIDC provider are available in [mock-oidc.yaml](manifests/mock-oidc.yaml).

[mock-oidc.yaml](manifests/mock-oidc.yaml ':include')

---

## 2. SAM Hub Manifests

The manifests for the SAM Hub are available in [sam-hub.yaml](manifests/sam-hub.yaml).

[sam-hub.yaml](manifests/sam-hub.yaml ':include')

---

## 3. Configuring Google OIDC (Optional)

To use Google as the OIDC provider instead of the mock provider:

2.  **No Redirect URI required:** Because `sam-node` implements RFC 8252 (dynamic loopback port selection for native apps), you don't need to configure a specific Redirect URI when setting up a Desktop app. The authorization server will automatically allow loopback redirects.
3.  **Update Secret:** Update the `sam-hub-secret` in `sam-hub.yaml` with your Google credentials:
    ```yaml
    SAM_OIDC_ISSUER: "https://accounts.google.com"
    SAM_OIDC_ID: "<your-client-id>.apps.googleusercontent.com"
    SAM_OIDC_SECRET: "<your-client-secret>"
    ```

---

## 4. Local Testing with Kind

### Step 1: Create a Kind Cluster
```bash
kind create cluster --name sam-test
```

### Step 2: Run cloud-provider-kind
Run it in a separate terminal:
```bash
cloud-provider-kind
```

### Step 3: Load Images into Kind
```bash
kind load docker-image sam-hub:local --name sam-test
kind load docker-image sam-node:local --name sam-test
```

### Step 4: Apply Manifests

If using the **Mock OIDC Provider**:
```bash
kubectl apply -f mock-oidc.yaml
kubectl apply -f sam-hub.yaml
```

If using **Google OIDC**:
```bash
kubectl apply -f sam-hub.yaml
```

### Step 5: Get the External IP
You can use the following command to extract the allocated IP into an environment variable:

```bash
HUB_IP=$(kubectl get svc sam-hub -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

---

## 5. Connecting an Agent

To connect a `sam-node` to the hub, you just need the hub's external IP and port.

### Enrolling the Agent

To connect a `sam-node` to the hub for the first time, you need to enroll it. The node needs to authenticate with the hub using a JWT token.

If you are using the **Mock OIDC Provider**, the node can fetch the token automatically from the mock provider's token endpoint.

1. **Get the Mock OIDC Service IP:**
   ```bash
   MOCK_IP=$(kubectl get svc mock-oidc -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   ```

2. **Run the Node with Token URL:**
   ```bash
   sam-node run \
     --hub "$HUB_IP:4002" \
     --token-url "http://$MOCK_IP:18080/token"
   ```

If you are using **Google OIDC**, you must obtain a valid Google ID token for your user and pass it via the `--jwt` flag:
```bash
sam-node run \
  --hub "$HUB_IP:4002" \
  --jwt "<your-google-id-token>"
```

Once enrolled, identity is stored in the local database, and you can run without authentication flags:
```bash
sam-node run \
  --hub "$HUB_IP:4002"
```

---

## 6. Automating Node Deployment

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
        - "sam-hub:4002"
        - "--token-url"
        - "http://mock-oidc:18080/token"
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
*   **How to use:** Pass the `--token-url`, `--client-id`, and `--client-secret` flags to `sam-node run`.
*   **Example:**
```bash
sam-node run \
  --hub "hub.example.com:4002" \
  --token-url "https://oauth2.googleapis.com/token" \
  --client-id "$SAM_OIDC_ID" \
  --client-secret "$SAM_OIDC_SECRET"
```

#### 2. Native App Authorization Code Flow (Human Intervention)
*   **Description:** For devices operated by humans, this uses the standard Authorization Code Flow with PKCE for native apps (RFC 8252). `sam-node` spins up a temporary local HTTP server, opens your browser, and receives the authentication token locally via an ephemeral loopback address.
*   **Use Case:** When a human operator is enrolling a node manually via their local terminal.
*   **How to use:** When you omit the `--jwt` or `--token-url` flags (or pass the OIDC issuer flag interactively), the node opens the browser and completes the flow without needing to enter complex passwords in the CLI. Alternatively, you can obtain a token yourself and pass it via the `--jwt` flag.
*   **Example:**
```bash
sam-node run \
  --hub "hub.example.com:4002" \
  --jwt "eyJhbGciOiJSUzI1NiIs..."
```

#### 3. Workload Identity Federation (Secretless Kubernetes)
*   **Description:** The current best practice in Kubernetes. It removes the need for static secrets entirely. The machine proves its identity based on where it is running by presenting a ServiceAccount token (a signed JWT issued by the K8s API).
*   **Use Case:** Production Kubernetes deployments.
*   **How it works:** The Pod has a ServiceAccount token mounted. The Pod presents this token to the `sam-hub`. The hub verifies it by calling back to the Kubernetes OIDC discovery endpoint.
*   **How to use:** Pass the path to the mounted ServiceAccount token to the `--jwt-path` flag.
*   **Example:**
```bash
sam-node run \
  --hub "hub.example.com:4002" \
  --jwt-path "/var/run/secrets/kubernetes.io/serviceaccount/token"
```
> [!NOTE]
> The `sam-hub` must be configured to trust the Kubernetes API server as an OIDC issuer for this flow to work.

---

## 7. Configuring Workload Identity in Kubernetes

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
        - "sam-hub:4002"
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
