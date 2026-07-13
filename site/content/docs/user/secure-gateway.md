---
title: "Secure Outbound Gateway Guide"
linkTitle: "Secure Outbound Gateway"
weight: 30
---

The Secure Outbound Gateway (`sam-box`) and the `nano-init` init-system allow operators to apply access control policies and secure credential injection for all outbound HTTP/HTTPS traffic originating from AI agent sandboxes.

---

## 1. Overview & Architecture

When running AI agents in isolated sandbox environments (such as gVisor, Kata Containers, or Docker with host network disabled), the agent's network namespace is entirely isolated. The Secure Outbound Gateway provides a transparent HTTP proxy model:

```mermaid
sequenceDiagram
    participant Agent as AI Agent (Inside Sandbox)
    participant Init as nano-init (Sandbox PID 1)
    participant Box as sam-box (Host / Shared Vol)
    participant Hub as sam-control-plane (Mesh)
    participant Upstream as External Service (e.g. OpenAI API)
    
    Agent->>Init: HTTP GET http://api.openai.com/v1/models (via HTTP_PROXY)
    Init->>Box: Forward raw bytes via Unix Domain Socket (UDS)
    Box->>Box: Parse & verify client's Biscuit token
    Box->>Hub: Verify policy rights
    Box->>Box: Lookup & Inject real API Key (e.g. Bearer sk-...)
    Box->>Upstream: HTTPS GET https://api.openai.com/v1/models (Upgraded to SSL)
    Upstream-->>Box: Response
    Box-->>Init: Forward response
    Init-->>Agent: Return response
```

### Rationale
* **Zero Trust Policy Enforcement**: Every request made by the agent sandbox is verified cryptographically using Biscuit tokens.
* **Transparent Secret Injection**: Agent sandboxes never see the real API keys or credentials. The gateway injects them at the network boundary before the request goes to the public internet.
* **Secure Upgrade**: Plain HTTP requests inside the sandbox are securely upgraded to HTTPS when forwarded to external targets.

---

## 2. Setting Up the Gateway (`sam-box`)

`sam-box` runs as a daemon on the host or inside a sidecar container, listening on a Unix Domain Socket (UDS). It operates as a first-class node in the Sovereign Agent Mesh.

### 1. Enrollment & Configuration
Since `sam-box` is built on top of the `sam-node` architecture, it supports the exact same 4 enrollment flows (JWT, file-based JWT, OIDC Client Credentials, and pre-shared Bootstrap tokens).

To join the mesh interactively:
```bash
sam-box join https://bananas.sam-mesh.dev
```

### 2. Running the Gateway
Start the gateway using the `run` command:
```bash
sam-box run \
  --uds-path=/var/run/sam/sam-box.sock \
  --secrets-file=/etc/sam/secrets.yaml \
  --log-level=info
```

#### Key Parameters:
* `--uds-path` (or `-u`): The path where the gateway will expose its Unix Domain Socket (e.g. `/var/run/sam/sam-box.sock`).
* `--secrets-file` (or `-s`): The YAML configuration file containing host-to-credential mappings for secret injection.

---

## 3. Configuring Secrets (`secrets.yaml`)

The secrets file specifies the credential injection policies for outbound destinations:

```yaml
# /etc/sam/secrets.yaml
"api.openai.com":
  kind: Bearer
  value: "sk-proj-xxxxxxxxxxxx"

"api.anthropic.com":
  kind: CustomHeader
  header_name: "x-api-key"
  value: "sk-ant-xxxxxxxxxxxx"

"custom-auth-service.internal":
  kind: BasicAuth
  value: "dXNlcjpwYXNz" # base64(username:password)
```

---

## 4. Running the Sandbox with `nano-init`

`nano-init` acts as PID 1 inside the agent's container. To enforce zero trust outbound security without port collisions or reliance on agent configuration:

1. **Dynamic Loopback Binding**: `nano-init` binds to a dynamic loopback port (`127.0.0.1:0`) for the blind UDS forwarder. This prevents `EADDRINUSE` address collisions when the agent app attempts to host web servers on port 80 or 443.
2. **Cooperative Proxy Configuration**: The allocated dynamic port is injected into the sandbox environment variables: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy`, and `all_proxy` set to `http://127.0.0.1:<assignedPort>`.
3. **Transparent Interception via C Hook**: To secure uncooperative agents or tools that bypass environment proxy configurations, `nano-init` injects a dynamic library (`LD_PRELOAD=/opt/sam/libinterceptor.so`). This hooks the C `connect()` syscall, intercepting outgoing TCP requests targeting ports 80 and 443, and transparently rewrites both the target IP to loopback (`127.0.0.1` or `::1`) and the port to `SAM_PROXY_PORT` (the assigned proxy port).

### Local Execution (Docker)

To run the sandbox locally:
```bash
# 1. Start sam-box on the host
sam-box run --uds-path /tmp/sam-box.sock --secrets-file secrets.yaml

# 2. Run the agent container wrapping it with nano-init
docker run --network none \
  -v /tmp/sam-box.sock:/var/run/sam-box.sock \
  -e TOKEN="<agent-biscuit-token>" \
  my-agent-image \
  /usr/local/bin/nano-init /var/run/sam-box.sock python3 agent.py
```

---

## 5. Kubernetes Deployment (Shared Volume Pod)

In a Kubernetes environment, you run `sam-box` as a sidecar container, and copy `nano-init` into the agent's namespace using an `initContainer` and a shared `emptyDir` volume:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-sandbox
spec:
  replicas: 1
  template:
    spec:
      serviceAccountName: sam-node-sa
      initContainers:
      - name: init-nano-init
        image: ghcr.io/google/sam-nano-init:latest
        command: ["/nano-init", "copy", "/shared-bin/nano-init"]
        volumeMounts:
        - name: shared-bin
          mountPath: /shared-bin
      containers:
      - name: agent
        image: python:3.11-alpine
        command:
          - "/shared-bin/nano-init"
          - "run"
          - "/var/run/sam/sam-box.sock"
          - "python3"
          - "agent.py"
        volumeMounts:
        - name: shared-bin
          mountPath: /shared-bin
        - name: sam-uds
          mountPath: /var/run/sam
      - name: sam-box
        image: ghcr.io/google/sam-box:latest
        args:
          - "run"
          - "--uds-path=/var/run/sam/sam-box.sock"
          - "--config=/etc/sam/sam-node.yaml"
          - "--secrets-file=/etc/sam/secrets.yaml"
          - "--hub=http://sam-control-plane.sam.svc.cluster.local:8080"
          - "--jwt-path=/var/run/secrets/tokens/sam-token"
        volumeMounts:
        - name: config-volume
          mountPath: /etc/sam
        - name: sam-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
        - name: sam-uds
          mountPath: /var/run/sam
      volumes:
      - name: shared-bin
        emptyDir: {}
      - name: sam-uds
        emptyDir: {}
      - name: config-volume
        configMap:
          name: sam-box-config
      - name: sam-token
        projected:
          sources:
          - serviceAccountToken:
              path: sam-token
              expirationSeconds: 3600
              audience: "sam-hub-audience"
```
