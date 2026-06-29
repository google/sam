---
title: "Integrating SAM with Google Antigravity"
linkTitle: "Integrating SAM with Google Antigravity"
---
You can connect your `sam-node` to Google Antigravity as an MCP server. By exposing the SAM Model Context Protocol (MCP) server to Antigravity, the agent can dynamically discover tools hosted by other peers in the mesh, describe them, and execute them to solve tasks.

## Overview

Antigravity natively supports Streamable HTTP MCP servers via the `serverUrl` configuration. Since `sam-node` implements the Streamable HTTP transport, you can connect it directly without any bridge.

## Prerequisites

- A running `sam-node` (default `http://localhost:8080`) and its `--api-token`.

## Configuration

Edit your Antigravity MCP configuration file:

- Path: `~/.gemini/config/mcp_config.json`

Add the node directly using its HTTP endpoint (replace `<YOUR_TOKEN>` with your `--api-token`):

```json
{
  "mcpServers": {
    "sam-mesh": {
      "serverUrl": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_TOKEN>"
      }
    }
  }
}
```

Antigravity will automatically discover the change. The `sam-node` tools — `discover_remote_services`, `find_remote_tools`, `describe_remote_tool`, and `call_remote_tool` — will then be available.

## Discovering and Invoking Remote Tools

The tool flow for Antigravity is as follows:

1. `discover_remote_services` → list active services and obtain their `peer_id`s.
2. `find_remote_tools` (`peer_id`) → list the tools a peer hosts.
3. `describe_remote_tool` (`peer_id`, `tool_name`) → fetch the tool's `input_schema`.
4. `call_remote_tool` (`peer_id`, `tool_name`, `arguments`) → invoke it across the mesh.

## Troubleshooting

* **Connection errors**: verify `sam-node` is reachable at the configured URL and that the bearer token matches `--api-token`.
* **Running `sam-node` in WSL or a container**: the `mcp-remote` bridge runs on the host, so that host must be able to reach the node's bind address. Bind the node to an address the host can reach (e.g. `0.0.0.0`).
