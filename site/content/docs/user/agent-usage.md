---
title: "Agent Usage & Connectivity Guide"
linkTitle: "Agent Usage"
weight: 20
---

SAM nodes (`sam-node`) act as local security gateways and tool proxies for your AI agents (such as Google Gemini, Claude Code, or Claude Desktop). This document explains how to authenticate a node to the mesh and configure your agents to use it.

---

## 1. Node Lifecycle Overview

Connecting your AI agent to the Sovereign Agent Mesh involves two phases:
```mermaid
sequenceDiagram
    actor User as Developer/Operator
    participant Node as sam-node (Local)
    participant Hub as sam-hub (Mesh)
    participant Agent as AI Agent (Gemini/Claude)
    
    Note over User,Hub: Phase 1: Mesh Join (OIDC Authorization)
    User->>Node: sam-node join <hub-url>
    Node->>Hub: Get Hub OIDC Info
    Hub-->>Node: OIDC Issuer, Client ID
    Node->>User: Display Login URL & Code
    User->>User: Login in Browser
    Node->>Hub: Exchange Code for Biscuit Identity
    Node->>Node: Persist Biscuit in Local Store (agent.db)

    Note over User,Agent: Phase 2: Agent Tool Invocation
    User->>Node: sam-node run --api-token "secret-key"
    Node->>Node: Start local MCP server on 127.0.0.1:8080
    Agent->>Node: Connect to local MCP (with Bearer "secret-key")
    Agent->>Node: Call Remote P2P Tool
    Node->>Hub: Verify Biscuit / Allowed Policies
    Node-->>Agent: Execute tool and return result
```

---

## 2. Phase 1: Joining the Mesh (`sam-node join`)

Before starting the node daemon, you must authorize your node and obtain a cryptographic Biscuit identity.

### Standard Login
Run the `join` command, pointing to the mesh control hub:
```bash
sam-node join https://bananas.sam-mesh.dev
```

*   **Browser Flow**: The CLI will discover the OIDC credentials from the hub, print an OIDC authorization URL, and attempt to open your system's default web browser automatically.
*   **Approval**: Log in with your corporate or identity credentials (e.g. Google Accounts), approve the authorization request, and return to the terminal. The node will automatically exchange the credentials for a Biscuit token and save it to `~/.config/sam-mesh/agent.db`.

### Headless (Server) Login
If you are running the node on a remote server via SSH (without a web browser), force headless out-of-band mode:
```bash
sam-node join https://bananas.sam-mesh.dev --headless
```
The CLI will print a verification URL and code (e.g. `https://google.com/device` and `ABCD-EFGH`). Open this URL on your local laptop, enter the code, complete the login, and the remote terminal session will activate automatically.

### Automatic Token Renewal
To allow long-lived nodes to automatically renew their tokens in the background, request offline access (refreshes the OIDC session):
```bash
sam-node join https://bananas.sam-mesh.dev --offline-access
```

---

## 3. Phase 2: Running the Node daemon (`sam-node run`)

Once authorized, you start the node gateway. The gateway spins up a local Model Context Protocol (MCP) server.

Run the node daemon, securing the local API endpoint with a custom token:
```bash
sam-node run --api-token "my-agent-super-token-123" --bind-addr "127.0.0.1:8080"
```

### Key CLI Parameters
*   `--bind-addr`: The local TCP address where the node's local HTTP server runs (default: `127.0.0.1:8080`).
*   `--api-token`: A security token required by any local AI agent attempting to connect to your node.
*   `--data-dir`: Custom path to store configurations and Biscuit tokens (defaults to `~/.config/sam-mesh` or env `SAM_DATA_DIR`).

---

## 4. Connecting your AI Agents

Your AI agent connects to the node's local MCP server. The local server translates standard MCP queries (like `listTools` or `callTool`) into secure P2P mesh commands.

### Exposing the API
The local MCP endpoint is served via **HTTP Server-Sent Events (SSE)** at:
`http://127.0.0.1:8080/mcp`

### Authentication
When configuring your agent client, you must pass the API token in the headers:
```http
Authorization: Bearer my-agent-super-token-123
```

### Specific Integration Guides
Explore our step-by-step guides for integrating your node with popular agent clients:
*   🚀 **[Google Gemini AI Agent](../integrations/gemini.md)**: Connect using Python scripts and the google-genai SDK.
*   💻 **[Claude Desktop](../integrations/claude-desktop.md)**: Expose P2P tools directly to your Claude Desktop application menu.
*   🤖 **[Claude Code](../integrations/claude-code.md)**: Add your local node tools directly to the Claude CLI.
*   🔌 **[OpenClaw](../integrations/openclaw.md)**: Setup remote tool bridges for OpenClaw clusters.
