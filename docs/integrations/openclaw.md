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

2. Inspect the bridged tools: Confirm the server entry and its connection details.
   ```bash
   openclaw mcp show p2p-mesh-node
   ```

## Discovering and Invoking Remote Tools

OpenClaw is a generic MCP client and exposes no SAM-specific CLI flags. Once the bridge is active, the tools that `sam-node` provides — `discover_remote_services`, `find_remote_tools`, `describe_remote_tool`, and `call_remote_tool` — are surfaced directly to your agent, which calls them like any other tool. The flow mirrors the local MCP API:

1. **Discover services**: the agent calls `discover_remote_services` (e.g. with `{"type": "mcp"}`) to list active MCP services on the mesh and obtain their `peer_id`s.

2. **Find remote tools**: the agent calls `find_remote_tools`, passing the target `peer_id`, to list the tools that peer hosts.

3. **Describe a remote tool**: the agent calls `describe_remote_tool`, passing the target `peer_id` and the namespaced `tool_name`, to fetch the tool's `input_schema`. This is required to learn the expected argument structure before invoking it.

4. **Invoke a remote tool**: the agent calls `call_remote_tool`, passing the target `peer_id`, the namespaced `tool_name` (e.g. `everything.get-sum`), and the tool's `arguments` (matching the schema from the previous step). Your local `sam-node` proxies the call across the P2P mesh and returns the result.

Because these tools are surfaced automatically, no remote tool needs to be registered individually in OpenClaw.

## Troubleshooting

* Connection Issues: Ensure `sam-node` is reachable at the configured URL (default `http://localhost:8080/mcp/events`).
* Authentication: Double-check that the `Authorization` header matches the `--api-token` provided to your `sam-node`.
* Gateway Status: Use `openclaw status` to confirm the gateway is running and the MCP bridge is active.
