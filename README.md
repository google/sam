# SAM: Sovereign Agent Mesh

<img alt="SAM" src="docs/sam_logo.png" />

SAM is a smart network built for autonomous AI agents:

*   **Zero Config:** Nodes discover each other and build the P2P network automatically.
*   **Zero Trust:** Every connection, node, and packet is strictly authenticated.
*   **Agentic Network:** Formed by lightweight nodes (`sam-node`) that provide self-healing, P2P connectivity, allowing autonomous agents to plug in, communicate, and invoke tools dynamically.
*   **Portability:** Cryptographic identities are environment-agnostic, allowing seamless node mobility across cloud, local, and edge environments.

---

## Architecture Components

*   `sam-hub`: The control plane for identity mapping and policy distribution.
*   `sam-node`: The P2P nodes providing the mesh transport layer and local MCP interfaces.

---

## Documentation

Start exploring the Sovereign Agent Mesh:

### For Users & Operators
Get a node running on the public testnet (`bananas.sam-mesh.dev`) in minutes:
- 🚀 **[User Quick Start Guide](docs/quickstart.md)**: Connect and run a SAM node using Docker and query the local MCP server via `curl`.
- 📖 **[CLI Reference](docs/cli/reference.md)**: Comprehensive CLI reference and configurations.
- 📡 **[Testnet Validation Tutorial](docs/testnet-validation.md)**: Real-time verification, remote tool invocation, and HTTP stream proxies.

### For Developers & Contributors
Compile from source, run local clusters, or execute tests:
- 🛠️ **[Developer Guide](docs/development.md)**: Prereqs, compilation, local hub setup, and Kubernetes Kind deployment.
- 🧪 **[Testing Guide](docs/testing.md)**: Go tests, E2E BATS, and containerized mesh execution.

---

## License

See [LICENSE](LICENSE).

## Disclaimer

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).
