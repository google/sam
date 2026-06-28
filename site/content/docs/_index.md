---
title: "SAM Documentation"
linkTitle: "Documentation"
---
SAM (Sovereign Agent Mesh) is a smart, zero-config, zero-trust P2P network built for autonomous AI agents.

## Architecture

*   **`sam-hub`**: The control plane for identity mapping, token issuing, and policy distribution.
*   **`sam-node`**: The P2P nodes providing the mesh transport layer, self-healing connectivity, and local Model Context Protocol (MCP) HTTP interfaces.

---

## Where to Start

### For Users & Operators
Get a node running on the public testnet (`bananas.sam-mesh.dev`) in minutes:
- 🚀 **[User Quick Start Guide](quickstart.md)**: Connect and run a SAM node using binaries or Docker, and query the local MCP server.
- 🤖 **[Agent Integration Guide](user/agent-usage.md)**: Connect Google Gemini, Claude, and other AI agents to your SAM node to call tools across the mesh.
- 📡 **[Testnet Validation Tutorial](development/testnet-validation.md)**: Real-time verification, remote tool invocation, and HTTP stream proxies.

### For Developers & Contributors
Compile from source, run local clusters, or execute tests:
- 🛠️ **[Developer Guide](development/_index.md)**: Prereqs, compilation, local hub setup, and Kubernetes Kind deployment.
- 🧪 **[Testing Guide](development/testing.md)**: Go tests, E2E BATS, and containerized mesh execution.
