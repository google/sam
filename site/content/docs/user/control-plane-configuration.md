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

## 3. Configuring Role-Based Policies (Dynamic API)

The Control Plane dynamically issues permissions inside the Biscuit token based on identity claims (users or groups) mapped to specific roles in the database.

The policy defines what endpoints and services agents are permitted to use:
* **`allowed_targets`**: Restricts which logical endpoints the agent can route connections to. Use resolved Biscuit facts: `group:<name>`, `user:<sub-id>`, `email:<email>`, `role:<role-name>`, or `node:<peer-id>`.
* **`allowed_services`**: Restricts the application-level services the agent can invoke. Services are prefixed by their protocol type and URI scheme (e.g., `mcp://local-shell-tools` or `inference://openrouter`). Wildcards are supported (e.g., `mcp://*`).

### Seeding Policies via REST API
Admins manage policies by sending a JSON payload to the `/policies` endpoint.

```json
{
  "roles": [
    {
      "name": "developer-role",
      "allowed_targets": ["group:dev-nodes", "email:dev-lead@example.com", "user:auth0|123456", "node:12D3KooWSpecificDevNodeId"],
      "allowed_services": ["mcp://local-shell-tools", "mcp://git-helper", "inference://openrouter"]
    },
    {
      "name": "admin-role",
      "allowed_targets": ["group:all-nodes", "role:admin"],
      "allowed_services": ["mcp://*", "inference://*", "system://*"]
    }
  ],
  "bindings": [
    {
      "role": "admin-role",
      "members": ["email:alice@example.com", "user:auth0|123456"]
    },
    {
      "role": "developer-role",
      "members": ["group:eng-team"]
    }
  ]
}
```

### 3.1 Binary Capability Roles (Zero Trust)
To enforce the principle of least privilege, the Sovereign Agent Mesh implements binary-level capability authorization. Every binary connecting to the mesh must request its specific target role during enrollment:
- `sam-node` requests `sam:role:node` (Default agent capability)
- `sam-box` requests `sam:role:sambox` (Secure Gateway sidecar)
- `sam-router` requests `sam:role:router` (P2P routing and relay service)

The Hub control plane validates that the enrolling client is authorized for the requested role before issuing the Biscuit identity token:
1. **Node Fallback**: By default, any successfully authenticated OIDC identity or generic bootstrap token can claim the `sam:role:node` role.
2. **Explicit Bindings**: The higher-privilege capability roles `sam:role:router` and `sam:role:sambox` must be explicitly authorized to the user/service account by mapping the role name in bindings. For example:

```json
"bindings": [
  {
    "role": "sam:role:router",
    "members": ["group:mesh-routers"]
  },
  {
    "role": "sam:role:sambox",
    "members": ["user:gateway-pod-sa"]
  }
]
```

If a binary requests a capability role it is not authorized for, enrollment fails immediately. If a client attempts to start using a token that lacks its binary's required role, startup aborts.

---

## 4. Bootstrapping Example

Here is a script demonstrating how to boot both services in a secure development environment:

```bash
# 1. Start the Control Plane (using SQLite)
./bin/sam-control-plane \
  --issuer "https://accounts.google.com" \
  --allowed-audiences "my-google-client-id.apps.googleusercontent.com" \
  --bind-address "0.0.0.0:8080" \
  --admin-token "super-secret-admin-token"

# 2. Seed baseline policy via REST API
curl -X POST \
  -H "Authorization: Bearer super-secret-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "roles": [{"name": "sam:role:node", "allowed_services": ["mcp://*"], "allowed_targets": ["*"]}],
    "bindings": [{"role": "sam:role:node", "members": ["group:developers"]}]
  }' \
  http://127.0.0.1:8080/policies

# 3. In another shell, start the Router using a bootstrap JWT or token
./bin/sam-router \
  --control-plane "http://127.0.0.1:8080" \
  --listen "/ip4/0.0.0.0/tcp/5001" \
  --listen "/ip4/0.0.0.0/udp/5001/quic-v1" \
  --keys-path "./router.key" \
  --oidc-token "my-router-jwt-token"
```

---

## 5. Token Refresh & Session Revocation

To enforce centralized access control without sacrificing offline verification performance at the edge, SAM implements a decoupled token refresh and session revocation model.

### Lifespan Model

1. **Short-Lived Biscuit Tokens (TTL = 24 Hours)**:
   All minted Biscuit tokens are cryptographically bound to a strict 24-hour expiration. Peers verify this expiration locally without hitting the Control Plane.
2. **Long-Lived Sessions (The Right to Refresh)**:
   * **OIDC Interactive Enrollment**: 90-day database session limit. After 90 days, the user must re-enroll interactively.
   * **Bootstrap Flow (Headless Nodes/Routers)**: Infinite session limit (sessions never expire).

### Proactive Refresh Lifecycle

Nodes and Routers run a background task that periodically checks the remaining Biscuit expiration:
* **Check Interval**: Every 10 minutes (`api.TokenRefreshCheckInterval`).
* **Threshold**: When the remaining token lifespan is less than 20% of its initial TTL (~4.8 hours remaining), the daemon proactively trades the expiring Biscuit for a fresh one.
* **Challenge Handshake**: The client signs a current timestamp using its private key and sends it to the Control Plane `/refresh` endpoint along with its expiring Biscuit in the `Authorization: Bearer <token>` header. The Control Plane verifies the signature against the registered node's public key in the database before issuing a new Biscuit.

### Administrative Revocation

Administrators can immediately revoke any active session to disable a node's ability to renew its token.
* **Endpoint**: `POST /admin/revoke`
* **Authentication**: Requires the `--admin-token` in the headers.
* **Payload**:
  ```json
  {
    "peer_id": "12D3KooW..."
  }
  ```
* **Enforcement**: Revoked nodes are marked as banned in the database. When the node next attempts a proactive `/refresh` handshake, the request is denied with a `403 Forbidden` status, and the node's local daemon immediately terminates.

---

## 6. Headless Node Enrollment (Bootstrap Token Flow)

To enroll a headless server, router, or background daemon that cannot complete interactive OIDC authentication, SAM supports a **Bootstrap Token** flow.

### Step 1: Generate a Bootstrap Token

An administrator with the `admin-token` can dynamically generate a time-bounded, single-use bootstrap token:

```bash
curl -X POST \
  -H "Authorization: Bearer <your-admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "sam:role:node", "ttl_hours": 24, "max_usages": 1, "description": "Headless node deployment token"}' \
  http://<control-plane-ip>:8080/admin/bootstrap-tokens
```

This returns a JSON response containing the plaintext token:
```json
{
  "id": "62e92ffca...",
  "token": "sam-bt-72fb0175788dee0...",
  "role": "sam:role:node",
  "expires_at": "2026-07-12T15:00:00Z"
}
```

### Step 2: Request Enrollment on the Node

Run the node `join` command with the generated token:

```bash
sam-node join --bootstrap-token sam-bt-72fb0175788dee0... http://<control-plane-ip>:8080
```

The node submits its enrollment request and waits (polls) for approval.

### Step 3: Approve the Enrollment

Administrators can review pending enrollment requests:

```bash
# List all pending enrollments
curl -H "Authorization: Bearer <your-admin-token>" http://<control-plane-ip>:8080/admin/enrollments
```

To approve the request and issue the node its identity Biscuit:

```bash
curl -X POST \
  -H "Authorization: Bearer <your-admin-token>" \
  http://<control-plane-ip>:8080/admin/enrollments/<request-id>/approve
```

Alternatively, you can boot the control plane with `--auto-approve-enrollment` to automatically approve all valid bootstrap token requests without manual gates.

