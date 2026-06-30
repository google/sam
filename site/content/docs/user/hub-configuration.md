---
title: "Hub Configuration Guide"
linkTitle: "Hub Configuration"
weight: 10
---

The `sam-hub` acts as the control plane for the Sovereign Agent Mesh. It is responsible for bridging user identities from OpenID Connect (OIDC) providers, issuing cryptographically signed Biscuit authorization tokens, and distributing network and tool policies to nodes.

---

## 1. Core Services

When you run `sam-hub`, it launches two core service endpoints:
1. **libp2p P2P Endpoint**: Used by `sam-node` clients to execute cryptographic handshakes and perform DHT resource discovery.
2. **HTTP/HTTPS Service Endpoint**: Used for health status checks (`/healthz`), prometheus metrics (`/metrics`), and administrative commands (like banning nodes).

---

## 2. Command-Line Arguments & Environment Variables

The hub is highly configurable. Each setting can be passed as a command-line flag or bound to a corresponding environment variable:

| CLI Flag | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `--issuer` | `SAM_OIDC_ISSUER` | `https://accounts.google.com` | Comma-separated list of trusted OIDC Provider URLs. |
| `--client-id` | `SAM_OIDC_ID` | *None* | Client ID registered with the OIDC provider. |
| `--key` | `SAM_HUB_KEY` | *None* | Private Key seed (32-byte hexadecimal string) used to sign Biscuit tokens. |
| `--listen` | *None* | `[]` | Comma-separated libp2p multiaddrs to listen on (e.g. `/ip4/0.0.0.0/tcp/9090`). |
| `--bind-address` | *None* | `:9090` | Host and port to listen on for the HTTP/HTTPS admin service. |
| `--policy-file` | *None* | `policies.yaml` | Path to the YAML file defining authorization roles and bindings. |
| `--allowed-audiences` | *None* | `sam-mesh-audience` | Comma-separated list of allowed JWT audiences. |
| `--insecure-skip-tls-verify` | *None* | `false` | Set to `true` to skip certificate validation for development/testing OIDC providers. |
| `--keys-db` | *None* | `keys.db` | Path to the BoltDB file storing public/private keys for token validation. |
| `--admin-token` | *None* | *None* | Secret token string required in the HTTP Header `Authorization: Bearer <token>` for admin operations. |
| `--tls-cert-file` | *None* | *None* | Path to the TLS certificate file (enables HTTPS on the admin server). |
| `--tls-key-file` | *None* | *None* | Path to the TLS private key file. |

---

## 3. Configuring Role-Based Policies (`policies.yaml`)

The hub dynamically issues permissions inside the Biscuit token based on identity claims (users or groups) mapped to specific roles in the policy file. 

The policy defines what endpoints and services agents are permitted to use:
* **`allowed_targets`**: Acts similar to Active Directory network groups. This restricts which logical endpoints the agent can route connections to. **Note: IP address ranges are not allowed.** Instead, use the format of the resolved Biscuit facts: `group:<name>`, `user:<sub-id>`, `email:<email>`, `role:<role-name>`, or `node:<peer-id>`.
* **`allowed_services`**: Restricts the application-level services the agent can invoke. Services are prefixed by their protocol type (e.g., `mcp:local-shell-tools` or `inference:openrouter`).

> [!NOTE]
> SAM natively supports prefix and suffix wildcards in `allowed_services`. You can grant access to an entire type via `mcp:*`, allow prefix matching like `mcp:dev-*`, suffix matching like `mcp:*-prod`, or grant global access to everything via `*`.

### Example Policy Mapping
Create a `policies.yaml` file in the directory where you run `sam-hub`:

```yaml
version: v1alpha1

# Define authorization roles and their specific network/tool permissions
roles:
  developer-role:
    allowed_targets:
      - "group:dev-nodes"
      - "email:dev-lead@example.com"
      - "user:auth0|123456"
      - "node:12D3KooWSpecificDevNodeId"
    allowed_services:
      - "mcp:local-shell-tools"
      - "mcp:git-helper"
      - "inference:openrouter"
  
  admin-role:
    allowed_targets:
      - "group:all-nodes"
      - "role:admin"
    allowed_services:
      - "mcp:*"
      - "inference:*"
      - "system:*"

# Bind OIDC user subs, emails, or group claims to roles
bindings:
  - email: "alice@example.com"
    role: "admin-role"
  - user: "auth0|123456"
    role: "admin-role"
  - group: "eng-team"
    role: "developer-role"
```

---

## 4. Bootstrapping Example

Here is a script demonstrating how to boot the hub in a secure development environment using Google Accounts as the OIDC provider:

```bash
# 1. Generate a secure 32-byte signing seed
export SAM_HUB_KEY=$(openssl rand -hex 32)

# 2. Configure environment settings
export SAM_OIDC_ISSUER="https://accounts.google.com"
export SAM_OIDC_ID="my-google-client-id.apps.googleusercontent.com"

# 3. Launch sam-hub with HTTPS and policies configured
./bin/sam-hub \
  --listen "/ip4/0.0.0.0/tcp/5001/udp/5001/quic-v1" \
  --policy-file "./policies.yaml" \
  --bind-address "0.0.0.0:9090" \
  --admin-token "super-secret-admin-token" \
  --tls-cert-file "/etc/sam/certs/hub.crt" \
  --tls-key-file "/etc/sam/certs/hub.key"
```
