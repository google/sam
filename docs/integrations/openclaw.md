# Integrating SAM with OpenClaw

You can seamlessly integrate your `sam-node` as a remote MCP server in [OpenClaw](https://openclaw.ai), allowing your agents to dynamically discover and invoke tools across the mesh.

## Overview

By configuring your `sam-node` as an MCP server, you enable your OpenClaw agents to access the P2P mesh, discovering tools from remote nodes and executing operations as if they were local.

## Configuration

To bridge your local `sam-node` into your OpenClaw agent runtime, use the `openclaw mcp` CLI. Ensure your node is running and identify the API token configured in your `sam-node` launch arguments.

```bash
# Add your local sam-node as an MCP server
# Replace <YOUR_TOKEN> with the token used in --api-token
openclaw mcp set p2p-mesh-node '{
  "url": "http://localhost:8080/mcp/events",
  "transport": "sse",
  "headers": {
    "Authorization": "Bearer <YOUR_TOKEN>"
  }
}'
```

## Verification

Once configured, restart your OpenClaw gateway to initialize the bridge. You can verify the configuration and connectivity with the following commands:

1. List configured servers: Ensure `p2p-mesh-node` appears in the registry.
   ```bash
   openclaw mcp list
   ```

2. Discover remote tools: From within your OpenClaw agent, you can now discover and invoke tools hosted on other nodes in the mesh.
   ```bash
   # List tools from a discovered remote peer
   openclaw mcp tool-list --peer <PEER_ID>
   ```

3. Remote invocation: Use the discovered tools directly in your agent's available toolset, enabling autonomous agents to invoke remote operations across the SAM mesh dynamically.

## Troubleshooting

* Connection Issues: Ensure `sam-node` is reachable at the configured URL (default `http://localhost:8080/mcp/events`).
* Authentication: Double-check that the `Authorization` header matches the `--api-token` provided to your `sam-node`.
* Gateway Status: Use `openclaw status` to confirm the gateway is running and the MCP bridge is active.
