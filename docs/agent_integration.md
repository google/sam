# Agent Integration Guide

SAM is designed to be the networking layer for autonomous AI agents. The easiest way for your agent to interact with the mesh is through the **Model Context Protocol (MCP)** exposed locally by your node.

Every `sam-node` runs a local MCP server that allows agents to:
- Discover tools available on the mesh.
- Connect to remote peers securely.
- Query mesh information (e.g. `get_mesh_info`).
- Call tools remotely (via `call_remote_tool`).

## Connecting via MCP

The `sam-node` exposes the MCP server over HTTP Server-Sent Events (SSE). By default, it listens at `127.0.0.1:8080`.

The repository provides a Python SDK (`sam-mcp-python`) which implements the MCP client.

### Prerequisites

You need the `sam_mcp` package installed. From the repo root, run:

```bash
pip install ./sam-mcp-python
```

### Python SDK Demo

The following snippet demonstrates how to connect to the local node's MCP server, list the available tools, and call the `get_mesh_info` tool.

```python
import asyncio
import os
import sys
from sam_mcp.client import SamClient

async def main():
    # Connect to the local SAM node's MCP SSE endpoint
    # By default, sam-node listens at 127.0.0.1:8080
    url = os.environ.get("SAM_MCP_URL", "http://127.0.0.1:8080/mcp/events")
    print(f"Connecting to SAM Node at {url}")

    try:
        async with SamClient(server_url=url) as client:
            # Discover available tools provided by the SAM node
            tools = await client.get_tools()
            print(f"Discovered {len(tools)} tools:")
            for tool in tools:
                print(f" - {tool['name']}: {tool['description']}")

            # Call the get_mesh_info tool to get information about the mesh
            print("\nCalling get_mesh_info tool...")
            result = await client.call_tool("get_mesh_info", {})
            print("Result:")
            print(result)

    except Exception as e:
        print(f"Error connecting to SAM Node: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
```

*(You can find this snippet at `docs/snippets/agent_demo.py`)*

### Example Output

When you run the demo while a `sam-node` is running locally, you'll see output similar to this:

```
Connecting to SAM Node at http://127.0.0.1:8080/mcp/events
Discovered tools:
 - get_mesh_info: Get information about the mesh network
 - call_remote_tool: Call an MCP tool on a remote agent

Calling get_mesh_info tool...
Result:
{'known_peers': [...], 'connected_peers': [...], 'dht_size': 1, 'hub_peer_id': '...'}
```
