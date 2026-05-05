# SAM: Sovereign Agent Mesh

<img alt="SAM" src="docs/sam_logo.png" />

SAM is a smart network built for autonomous agents:

*   **Zero Config:** Nodes discover each other and build the network automatically.
*   **Zero Trust:** Every connection, node, and packet is strictly authenticated.
*   **Agentic Network:** Built for agents to use. The nodes provide the self-healing, peer-to-peer infrastructure, allowing autonomous agents to seamlessly plug in, communicate, and operate across the mesh.
*   **Portability:** Environment-agnostic and IP-independent. Network identity is cryptographic and travels with the node, enabling mobility across cloud, edge, and local setups.


- `sam-hub`: The control plane for identity and policy distribution.
- `sam-node`: The lightweight agents that form the actual peer-to-peer mesh.

## Build

```bash
make build
./bin/sam-node --help
./bin/sam-hub --help
```

## Basic Usage

### 1. Run the hub

```bash
SAM_OIDC_ISSUER=https://issuer.example.com \
SAM_OIDC_ID=sam-client \
SAM_OIDC_SECRET=sam-secret \
SAM_HUB_KEY=$(openssl rand -hex 32) \
./bin/sam-hub
```

### 2. Login a node

```bash
./bin/sam-node login --hub http://localhost:8080
```

This prints a login URL. After authenticating in browser, paste the returned biscuit token back into the CLI prompt.

### 3. Run a node

```bash
./bin/sam-node run
```

Or pass a token directly:

```bash
./bin/sam-node run --token <identity-token>
```

## Local MCP Server

Each `sam-node` exposes a Model Context Protocol (MCP) server over HTTP Server-Sent Events (SSE) to allow local processes to discover the capabilities of the local agent and get information from the mesh.

By default, the server listens at `127.0.0.1:8080`. You can change this with the `--bind-addr` flag.

To query the mesh info via the MCP server, you can use the `mcp-client` tool provided in the repository:

```bash
./bin/mcp-client -url http://127.0.0.1:8080/mcp/events
```

## Testing

```bash
make test
make test-e2e
make test-e2e-container
```

`test-e2e-container` runs a containerized BATS framework that starts:

- a mock OIDC container
- a `sam-hub` container
- multiple `sam-node` containers

## Documentation

- Docs index: `docs/index.html`
- Project docs landing page: `docs/README.md`
- Quickstart: `docs/quickstart.md`
- CLI reference: `docs/cli/reference.md`
- Testing guide: `docs/testing.md`

## License

See [LICENSE](LICENSE).

## Disclaimer

This is not an officially supported Google product. This project is not eligible
for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
