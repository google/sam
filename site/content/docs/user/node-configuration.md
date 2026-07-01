---
title: "Node Configuration Guide"
linkTitle: "Node Configuration"
weight: 15
---

The `sam-node` acts as a local security gateway and tool proxy for AI agents. While the Hub acts as the central control plane, each Node independently defines its own local tool catalogue and enforces its own local security identity.

---

## 1. Node Configuration File (`sam-node.yaml`)

By default, `sam-node` runs without exposing any local tools to the mesh. To expose local tools or strictly enforce your node's network identity, you must create a Node configuration file and pass it to the daemon using the `--config` flag:

```bash
sam-node run --config ./sam-node.yaml --api-token "secret"
```

### Configuration Schema

The `sam-node.yaml` file supports defining local **Services** and local **Attenuation** security rules.

```yaml
version: "v1alpha1"

# 1. Define Local Services
services:
  # Example: Expose a local CLI MCP server to the mesh
  - type: mcp
    name: local-shell-tools
    description: "Execute bash commands safely in a local container"
    command: ["npx", "-y", "@modelcontextprotocol/server-everything"]

  # Example: Expose a local inference endpoint
  - type: inference
    name: local-ollama
    description: "DeepSeek local inference proxy"
    target_url: "http://localhost:11434"

# 2. Define Local Security Identity (Zero Trust)
attenuation:
  rules:
    # Example: Inject custom Datalog facts asserting local node state
    - 'time(2026-06-30T00:00:00Z) <- true;'
  policies:
    # Example: Custom local deny rule restricting access from untrusted users
    - 'deny if user("untrusted_sub_id");'
```

---

## 2. Defining Local Services

The `services` array allows you to register endpoints that remote peers in the SAM Network can discover and execute (provided they possess the proper `granted_service_*` credentials issued by the Hub).

| Property | Description |
| :--- | :--- |
| `type` | The protocol protocol type. Supported values are `mcp` (Model Context Protocol), `inference`, or `a2a`. |
| `name` | The unique name of the service (e.g., `git-helper`). This must exactly match the name authorized by the Hub's `policies.yaml` (e.g., `mcp://git-helper`). |
| `description` | A human-readable description published to the mesh discovery catalogue. |
| `command` | *(For MCP)* The executable command array to spawn as a local subprocess (e.g. `["node", "index.js"]`). |
| `env` | *(For MCP)* Key-value environment variables passed to the subprocess. |
| `target_url` | *(For HTTP/Inference)* The upstream local URL to proxy traffic to. |

---

## 3. Defining Local Security (Target Attenuation)

In a Zero Trust architecture, the destination node is entirely responsible for verifying that it is the intended recipient of an incoming request.

While the Hub limits token capabilities based on target restrictions (e.g., `target_restricted()` or `target_unrestricted()`), the destination node evaluates these dynamically. The node automatically resolves its local identity context based on its configuration, generating facts internally (such as `allow_network_target($fact, $value)`).

If the caller's token has target restrictions, the connection will only be allowed if the token's `granted_target_*` facts match the dynamically injected identity of the node. You do **not** need to write manual Datalog rules to enforce this mechanism; it is baked directly into the node middleware via baseline policies.

### Local Custom Policies
You can further restrict access using the `attenuation` block. Local policies defined here are evaluated **before** the baseline rules. This means local administrators can write custom rules that explicitly `deny` access based on custom logic, overriding broad access granted by the Hub.

1. **`rules`**: Inject custom Datalog facts asserting local node state (e.g., `time($time)`).
2. **`policies`**: Add local restrictions (e.g., `deny if user("banned_user");`).
