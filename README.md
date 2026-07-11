# SAM: Sovereign Agent Mesh

<img alt="SAM" src="site/content/docs/sam_logo.png" />

SAM is a smart network built for autonomous AI agents:

*   **Zero Config:** Nodes discover each other and build the P2P network automatically.
*   **Zero Trust:** Every connection, node, and packet is strictly authenticated.
*   **Agentic Network:** Formed by lightweight nodes (`sam-node`) that provide self-healing, P2P connectivity, allowing autonomous agents to plug in, communicate, and invoke tools dynamically.
*   **Portability:** Cryptographic identities are environment-agnostic, allowing seamless node mobility across cloud, local, and edge environments.

---

## Architecture Components

*   `sam-control-plane`: The registry control plane for node identity registration, authorization policies, and router coordinating.
*   `sam-router`: The libp2p bootstrap nodes and relays providing data-plane connectivity and forwarding.
*   `sam-node`: The local node clients providing mesh transport integration and MCP sidecar routing.

---

## Documentation

Start exploring the Sovereign Agent Mesh:

### For Users & Operators
Get a node running on the public testnet (`bananas.sam-mesh.dev`) in minutes:
- 🚀 **[User Quick Start Guide](site/content/docs/quickstart.md)**: Connect and run a SAM node using binaries or Docker, and query the local MCP server.
- 🤖 **[Agent Integration Guides](site/content/docs/integrations/_index.md)**: Connect Google Gemini, Claude, and other AI agents to your SAM node to dynamically discover and call tools across the mesh.
- 📡 **[Testnet Validation Tutorial](site/content/docs/development/testnet-validation.md)**: Real-time verification, remote tool invocation, and HTTP stream proxies.

### For Developers & Contributors
Compile from source, run local clusters, or execute tests:
- 🛠️ **[Developer Guide](site/content/docs/development/_index.md)**: Prereqs, compilation, local hub setup, and Kubernetes Kind deployment.
- 🧪 **[Testing Guide](site/content/docs/development/testing.md)**: Go tests, E2E BATS, and containerized mesh execution.

---

## License

See [LICENSE](LICENSE).

## Disclaimer

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).
