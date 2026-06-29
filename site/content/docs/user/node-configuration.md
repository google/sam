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
    # Explicitly define this node's identity in the mesh
    - 'target("group:backend-nodes") <- true;'
    - 'target("email:db@example.com") <- true;'
  policies:
    # Enforce that the incoming caller's token contains a matching network_target 
    - 'allow if target($t), network_target($t);'
```

---

## 2. Defining Local Services

The `services` array allows you to register endpoints that remote peers in the SAM Network can discover and execute (provided they possess the proper `allow_service` credentials issued by the Hub).

| Property | Description |
| :--- | :--- |
| `type` | The protocol protocol type. Supported values are `mcp` (Model Context Protocol), `inference`, or `a2a`. |
| `name` | The unique name of the service (e.g., `git-helper`). This must exactly match the name authorized by the Hub's `policies.yaml` (e.g., `mcp:git-helper`). |
| `description` | A human-readable description published to the mesh discovery catalogue. |
| `command` | *(For MCP)* The executable command array to spawn as a local subprocess (e.g. `["node", "index.js"]`). |
| `env` | *(For MCP)* Key-value environment variables passed to the subprocess. |
| `target_url` | *(For HTTP/Inference)* The upstream local URL to proxy traffic to. |

---

## 3. Defining Local Security (Target Attenuation)

In a Zero Trust architecture, the destination node is entirely responsible for verifying that it is the intended recipient of an incoming request. 

While the Hub injects routing boundaries (like `network_target("group:backend-nodes")`) into the caller's token, the destination node will **ignore these targets by default** (relying solely on the Hub's service whitelist) unless you explicitly configure the node's local identity.

If your mesh operator utilizes `allowed_targets` to partition the network, your node **must** define its identity in the `attenuation` block to accept traffic:

1. **`rules`**: Inject Datalog facts asserting the node's identity (e.g. `target("group:backend-nodes") <- true;`).
2. **`policies`**: Add a local policy strictly enforcing that the incoming token possesses the matching capability (e.g. `allow if target($t), network_target($t);`).

If a calling node attempts to connect and its token does not contain the required `network_target` matching your local `target` rules, the connection will be cryptographically rejected.
