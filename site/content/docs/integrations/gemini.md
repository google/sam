---
title: "Running a Gemini AI Agent on the Mesh"
linkTitle: "Running a Gemini AI Agent on the Mesh"
---
This tutorial demonstrates how to connect a local AI Agent powered by Google Gemini (using the official `google-genai` SDK) to your local SAM node. 

By exposing the SAM Model Context Protocol (MCP) server to Gemini, the agent can dynamically discover tools hosted by other peers in the mesh, describe them, and execute them to solve tasks.

---

## Prerequisites

1. **Python 3.10+**: Ensure Python is installed on your host.
2. **SAM Node Running**: A local SAM node should be running and enrolled on the testnet (see the [Quick Start Guide](../quickstart.md)).
3. **Gemini API Key**: Obtain an API key from Google AI Studio and export it:
   ```bash
   export GEMINI_API_KEY="your-api-key-here"
   ```

---

## 1. Setup the Python Client

Go to the `sam-mcp-python` directory in the repository:

```bash
cd sam-mcp-python
```

Create a virtual environment and install the required dependencies:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the SAM Python SDK and Gemini SDK
pip install . google-genai
```

---

## 2. Run the Gemini Agent

Start the interactive agent:

```bash
python3 examples/gemini_agent.py
```

Upon starting, the script will:
1. Connect to the local SAM node's MCP server at `http://localhost:8080/mcp`.
2. Discover all tools currently available in the mesh.
3. Map the mesh tools to Gemini-compatible OpenAPI schemas.
4. Spin up a chat loop with Gemini (`gemini-2.5-flash`).

---

## 3. Interact with the Agent

Once the agent is online, you can prompt it in plain English. If a task requires tools registered in the mesh, Gemini will automatically call them.

### Example 1: Explore the Mesh
Ask the agent what it can see in the mesh:
```text
You > How many nodes are currently connected to the mesh? And what are their Peer IDs?

[Agent wants to call tool: get_mesh_info with args: {}]
[Tool Result]: {'connected_peers': ['12D3KooWD3m6Jfry...'], 'dht_size': 1, ...}

Agent > There is currently 1 active peer connected to the mesh with Peer ID 12D3KooWD3m6Jfry...
```

### Example 2: Call Remote Tools Dynamically
If another node on the mesh is hosting a tool (e.g. `everything.get-sum`), you can ask Gemini to compute a sum. It will find the tool, query its schema, and execute it:

```text
You > Can you sum 1234.5 and 5678.9 using a tool in the mesh?

[Agent wants to call tool: find_remote_tools with args: {}]
[Tool Result]: ... 'name': 'everything.get-sum', 'description': 'Sums two floats', 'peer_id': '12D3KooWD3m6Jfry...' ...

[Agent wants to call tool: describe_remote_tool with args: {'peer_id': '12D3KooWD3m6Jfry...', 'tool_name': 'everything.get-sum'}]
[Tool Result]: {'inputSchema': {'properties': {'a': {'type': 'number'}, 'b': {'type': 'number'}}, 'required': ['a', 'b']}}

[Agent wants to call tool: call_remote_tool with args: {'peer_id': '12D3KooWD3m6Jfry...', 'tool_name': 'everything.get-sum', 'arguments': {'a': 1234.5, 'b': 5678.9}}]
[Tool Result]: {'result': {'sum': 6913.4}}

Agent > The sum of 1234.5 and 5678.9 is 6913.4, calculated using the 'everything.get-sum' tool hosted on peer 12D3KooWD3m6Jfry...
```
