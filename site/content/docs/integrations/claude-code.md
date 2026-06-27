---
title: "Integrating SAM with Claude Code"
linkTitle: "Integrating SAM with Claude Code"
---
You can connect your `sam-node` to [Claude Code](https://claude.com/claude-code) as a remote MCP server, giving Claude Code agents the ability to discover and invoke tools across the SAM mesh.

## Overview

`sam-node` exposes a standard Model Context Protocol (MCP) server over HTTP Server-Sent Events (SSE). Claude Code is a generic MCP client, so once the server is registered its tools — `discover_remote_services`, `find_remote_tools`, `describe_remote_tool`, and `call_remote_tool` — are surfaced directly to your agent.

## Prerequisites

- A running `sam-node` with its local control-plane API reachable (default `http://localhost:8080`). See the [Quick Start](../quickstart.md).
- The `--api-token` you launched the node with.
- Claude Code installed (the `claude` CLI).

## Configuration

Register the node as an SSE MCP server. Replace `<YOUR_TOKEN>` with your `--api-token`:

```bash
claude mcp add --transport sse p2p-mesh-node \
  http://localhost:8080/mcp/events \
  --header "Authorization: Bearer <YOUR_TOKEN>"
```

By default the server is added at *local* scope (the current project only). Add `--scope user` to make it available in all your projects, or `--scope project` to write a shareable `.mcp.json` into your repository.

Alternatively, add it to a project `.mcp.json` directly:

```json
{
  "mcpServers": {
    "p2p-mesh-node": {
      "type": "sse",
      "url": "http://localhost:8080/mcp/events",
      "headers": {
        "Authorization": "Bearer <YOUR_TOKEN>"
      }
    }
  }
}
```

The `type` field is required for a remote server; omit it and the entry will not load. If a future `sam-node` release also exposes a streamable-HTTP endpoint, use `--transport http` (or `"type": "http"`) instead.

## Verification

```bash
# Confirm the server is registered and connected
claude mcp list
claude mcp get p2p-mesh-node
```

A healthy server reports `✔ Connected`. MCP tools are loaded at session start, so start (or restart) Claude Code and run `/mcp` to see `p2p-mesh-node` and its tools.

## Discovering and Invoking Remote Tools

Claude Code calls the tools `sam-node` exposes like any other tool. The flow mirrors the local MCP API:

1. **Discover services**: call `discover_remote_services` (e.g. with `{"type": "mcp"}`) to list active MCP services on the mesh and obtain their `peer_id`s.
2. **Find remote tools**: call `find_remote_tools`, passing the target `peer_id`, to list the tools that peer hosts.
3. **Describe a remote tool**: call `describe_remote_tool`, passing the `peer_id` and the namespaced `tool_name`, to fetch the tool's `input_schema` before invoking it.
4. **Invoke a remote tool**: call `call_remote_tool`, passing the `peer_id`, the namespaced `tool_name` (e.g. `everything.get-sum`), and the `arguments` matching that schema. Your local `sam-node` proxies the call across the P2P mesh and returns the result.

## Troubleshooting

* **Connection shows failed / 401**: verify the `Authorization` header matches the node's `--api-token`.
* **Server unreachable**: confirm `sam-node` is listening (default `http://localhost:8080`).
* **Tools not visible**: MCP servers load at session start — restart Claude Code and check `/mcp`.
* **Remove the server**: `claude mcp remove p2p-mesh-node -s user` (match the scope you used to add it).
