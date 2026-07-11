---
title: "SAM Documentation"
linkTitle: "Documentation"
---
SAM (Sovereign Agent Mesh) is a smart, zero-config, zero-trust P2P network built for autonomous AI agents. Think of it as a modern, zero-trust overlay network (similar to a private VPN), but specifically designed and scoped for agent-to-agent tool sharing and communication.

## Why SAM?

Instead of exposing your agent's tools (like local scripts, LLM endpoints, or internal APIs) to the public internet, SAM allows you to create secure, private mesh networks. This is especially critical because modern AI agents operate across highly heterogeneous environments—spanning cloud servers, on-premises datacenters, personal laptops, Raspberry Pis, and Android devices. SAM seamlessly connects them all, regardless of complex network topologies or NATs.

**Security & Trust Boundaries (Read This First!)**
* **Isolated by Default:** You do NOT join any mesh by default. You must explicitly configure the control plane (Hub) you want to join.
* **Closed by Default:** Joining a mesh does not expose your tools. By default, your node does not allow any services to be reached by others. You must explicitly configure policies to share tools.
* **Bring Your Own Control Plane (DIY):** While we offer public testnets, the core design allows you to host your own SAM control plane. You retain 100% control over your data, identities, and authorization policies.

---

## Where to Start

### "Easy Mode" (Public Testnet)
For the fastest way to get started and experiment, you can join our public beta testnet (`bananas.sam-mesh.dev`). *Note: While convenient, remember this is a public testnet. Ensure you only expose tools you are comfortable sharing in a testing environment.*

- 🚀 **[User Quick Start Guide](quickstart/)**: Connect and run a SAM node using binaries or Docker, and query the local MCP server.
- 🤖 **[Agent Integration Guide](user/agent-usage/)**: Connect Google Gemini, Claude, and other AI agents to your SAM node to call tools across the mesh.
- 📡 **[Testnet Validation Tutorial](development/testnet-validation/)**: Real-time verification, remote tool invocation, and HTTP stream proxies.

### "DIY Mode" (Self-Hosted for Developers & Operators)
Compile from source, run local clusters, host your own control plane, or execute tests:
- 🛠️ **[Developer Guide](development/)**: Prereqs, compilation, local hub setup, and Kubernetes Kind deployment.
- 🧪 **[Testing Guide](development/testing/)**: Go tests, E2E BATS, and containerized mesh execution.

---

## Architecture

*   **`sam-control-plane`**: The control plane for identity mapping, token issuing, and policy distribution.
*   **`sam-router`**: The GossipSub routing overlays and bootstrap points for the P2P mesh.
*   **`sam-node`**: The P2P nodes providing the mesh transport layer, self-healing connectivity, and local Model Context Protocol (MCP) HTTP interfaces.
