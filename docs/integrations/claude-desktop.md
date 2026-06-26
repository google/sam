# Integrating SAM with Claude Desktop

You can connect your `sam-node` to the [Claude Desktop](https://claude.com/download) app as an MCP server. Unlike [Claude Code](./claude-code.md), Claude Desktop has its own configuration and does **not** read Claude Code's MCP settings.

## Overview

Claude Desktop's `claude_desktop_config.json` natively launches **stdio** MCP servers (a local command). `sam-node` exposes an **SSE** server, so you bridge the two with [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) — a small stdio-to-remote proxy that Claude Desktop launches locally and that connects to your node's SSE endpoint.

> **Local node vs. Custom Connectors.** Use the `mcp-remote` bridge below for a `sam-node` running on your own machine: the bridge runs locally and can reach `localhost`. Claude's **Custom Connectors** UI is *not* suitable for a local node — Claude connects to connector URLs from Anthropic's cloud infrastructure, so the node would have to be reachable over the public internet. Reserve Custom Connectors for a publicly exposed SAM endpoint.

## Prerequisites

- A running `sam-node` (default `http://localhost:8080`) and its `--api-token`.
- [Node.js](https://nodejs.org) installed, which provides the `npx` used to run `mcp-remote`.
- Claude Desktop installed.

## Configuration

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Add the node through the `mcp-remote` bridge (replace `<YOUR_TOKEN>` with your `--api-token`):

```json
{
  "mcpServers": {
    "p2p-mesh-node": {
      "command": "npx",
      "args": [
        "mcp-remote@latest",
        "--sse",
        "http://localhost:8080/mcp/events",
        "--allow-http",
        "--header",
        "Authorization: Bearer <YOUR_TOKEN>"
      ]
    }
  }
}
```

`--allow-http` is required because the node is served over plain HTTP on the loopback interface rather than HTTPS.

Restart Claude Desktop for the change to take effect. The `sam-node` tools — `discover_remote_services`, `find_remote_tools`, `describe_remote_tool`, and `call_remote_tool` — then appear in the MCP tools menu (the connectors / plug icon).

## Discovering and Invoking Remote Tools

The tool flow is identical to the [Claude Code guide](./claude-code.md#discovering-and-invoking-remote-tools):

1. `discover_remote_services` → list active services and obtain their `peer_id`s.
2. `find_remote_tools` (`peer_id`) → list the tools a peer hosts.
3. `describe_remote_tool` (`peer_id`, `tool_name`) → fetch the tool's `input_schema`.
4. `call_remote_tool` (`peer_id`, `tool_name`, `arguments`) → invoke it across the mesh.

## Troubleshooting

* **Tools don't appear**: fully quit and reopen Claude Desktop, and confirm `npx` is on your `PATH`.
* **Connection errors**: verify `sam-node` is reachable at the configured URL and that the bearer token matches `--api-token`.
* **Running `sam-node` in WSL or a container**: the `mcp-remote` bridge runs on the Claude Desktop host, so that host must be able to reach the node's bind address. Bind the node to an address the host can reach (e.g. `0.0.0.0`) or set up port forwarding, rather than a container-only `127.0.0.1`.
* **Authentication header ignored**: pass the header as a single argument, `--header "Authorization: Bearer <YOUR_TOKEN>"`.
