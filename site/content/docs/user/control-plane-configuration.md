---
title: "Control Plane & Router Configuration Guide"
linkTitle: "Control Plane & Router Configuration"
weight: 10
---

The SAM architecture separates the OIDC capabilities control plane (`sam-control-plane`) from the GossipSub network routers (`sam-router`). 

---

## 1. SAM Control Plane (`sam-control-plane`)

The Control Plane is responsible for bridging user identities from trusted OIDC providers, issuing cryptographically signed Biscuit authorization tokens, and distributing network/tool policies to routers and nodes.

### Command-Line Arguments & Environment Variables

| CLI Flag | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `--issuer` | `SAM_OIDC_ISSUER` | *None* (Required) | Comma-separated list of trusted OIDC Provider URLs. |
| `--bind-address` | *None* | `0.0.0.0:8080` | Host and port to listen on for HTTP web API service. |
| `--db-driver` | *None* | `sqlite` | Database driver (`sqlite` or `postgres`). |
| `--db-dsn` | *None* | `control-plane.db` | Database DSN/Connection URL (e.g. `postgres://user:pass@host:5432/db`). |
| `--allowed-audiences` | *None* | `sam-mesh-audience` | Comma-separated list of allowed JWT audiences. |
| `--policy-file` | *None* | `policies.yaml` | Path to the YAML file defining authorization roles and bindings (bootstrapping only). |
| `--admin-token` | *None* | *None* | Secret token string required in the HTTP Header `Authorization: Bearer <token>` for admin operations. |
| `--insecure-skip-tls-verify` | *None* | `false` | Set to `true` to skip certificate validation for development/testing OIDC providers. |
| `--key-rotation-interval` | *None* | `24h` | Key rotation interval (e.g. `24h`). `0s` disables rotation. |
| `--key-grace-period` | *None* | `1h` | Key grace period for rotated keys. |
| `--lease-duration` | *None* | `15m` | Router lease registration TTL. |

---

## 2. SAM Router (`sam-router`)

The Router is a dedicated GossipSub helper that maintains stable network addresses (multiaddrs) and relays mesh overlays for discovery.

### Command-Line Arguments & Environment Variables

| CLI Flag | Default Value | Description |
| :--- | :--- | :--- |
| `--control-plane` | `http://127.0.0.1:8080` | Control Plane web service URL. |
| `--listen` | `/ip4/0.0.0.0/tcp/5001`, `/ip6/::/tcp/5001` | Comma-separated libp2p multiaddrs to listen on. |
| `--external-addr` | *None* | External multiaddrs to announce to control plane. |
| `--keys-path` | `router.key` | Path to save/load persistent private key (determines Peer ID). |
| `--jwt-path` | *None* | Path to file containing OIDC JWT token for enrollment. |
| `--oidc-token` | *None* | Direct OIDC ID token or bootstrap secret token for enrollment. |
| `--keys-sync-interval` | `5m` | Key synchronization polling interval. |
| `--lease-renew-interval` | `300s` | Lease renewal registration interval. |
| `--allow-loopback` | `false` | Allow loopback and link-local addresses for discovery (development only). |

---

## 3. Configuring Role-Based Policies (`policies.yaml`)

The Control Plane dynamically issues permissions inside the Biscuit token based on identity claims (users or groups) mapped to specific roles in the policy file. 

The policy defines what endpoints and services agents are permitted to use:
* **`allowed_targets`**: Restricts which logical endpoints the agent can route connections to. Use resolved Biscuit facts: `group:<name>`, `user:<sub-id>`, `email:<email>`, `role:<role-name>`, or `node:<peer-id>`.
* **`allowed_services`**: Restricts the application-level services the agent can invoke. Services are prefixed by their protocol type and URI scheme (e.g., `mcp://local-shell-tools` or `inference://openrouter`). Wildcards are supported (e.g., `mcp://*`).

### Example Policy Mapping
Create a `policies.yaml` file in the directory where you run `sam-control-plane`:

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
      - "mcp://local-shell-tools"
      - "mcp://git-helper"
      - "inference://openrouter"
  
  admin-role:
    allowed_targets:
      - "group:all-nodes"
      - "role:admin"
    allowed_services:
      - "mcp://*"
      - "inference://*"
      - "system://*"

# Bind OIDC user subs, emails, or group claims to roles
bindings:
  - members: ["email:alice@example.com"]
    role: "admin-role"
  - members: ["user:auth0|123456"]
    role: "admin-role"
  - members: ["group:eng-team"]
    role: "developer-role"
```

---

## 4. Bootstrapping Example

Here is a script demonstrating how to boot both services in a secure development environment:

```bash
# 1. Start the Control Plane (using SQLite and policies)
./bin/sam-control-plane \
  --issuer "https://accounts.google.com" \
  --allowed-audiences "my-google-client-id.apps.googleusercontent.com" \
  --policy-file "./policies.yaml" \
  --bind-address "0.0.0.0:8080" \
  --admin-token "super-secret-admin-token"

# 2. In another shell, start the Router using a bootstrap JWT or token
./bin/sam-router \
  --control-plane "http://127.0.0.1:8080" \
  --listen "/ip4/0.0.0.0/tcp/5001" \
  --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
  --keys-path "./router.key" \
  --oidc-token "my-router-jwt-token"
```
