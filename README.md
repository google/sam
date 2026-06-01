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

### 2. Join a mesh (Enroll node)

To register the node's cryptographic identity with the hub:

```bash
./bin/sam-node join http://localhost:8080
```

This initiates the interactive OIDC Device Authorization flow. It prints a URL to open in your browser for authentication. Once authorized, it automatically receives the node's Biscuit identity token and saves it (along with the derived node private key) inside the local data store.

### 3. Run the node

Start the node using the stored identity (note that `--api-token` is mandatory to protect the local API when not using mTLS):

```bash
./bin/sam-node run --api-token my-secret-token
```

Or run the node by explicitly passing OIDC credentials to dynamically authenticate and enroll on start:

```bash
./bin/sam-node run \
  --oidc-issuer https://issuer.example.com \
  --client-id <id> \
  --client-secret <secret> \
  --api-token my-secret-token
```

## Docker Quick Start

You can run the SAM node using Docker and the officially published image. To persist your node's identity, private key, and mesh discovery configuration across runs, use a host volume mounted to the container's data directory.

### 1. Join the Mesh (Enroll)

Run the container interactively to register your node with the community testnet (`https://bananas.sam-mesh.dev`):

```bash
docker run -it \
  -v $(pwd)/sam-data:/data \
  ghcr.io/google/sam-node:latest \
  join --data-dir /data https://bananas.sam-mesh.dev
```

- Follow the printed device authentication instructions in your browser.
- This generates the node identity and stores it inside `./sam-data/agent.db` on the host.

### 2. Run the Node

Start the background mesh node container using the stored identity. Make sure to publish the required libp2p ports (5001/UDP and 5002/TCP), set a secure `--api-token` to protect the local MCP/Sidecar API, and bind the HTTP server to `0.0.0.0:8080` so that it can be reached from the host:

```bash
docker run -d \
  --name sam-node \
  -v $(pwd)/sam-data:/data \
  -p 5001:5001/udp \
  -p 5002:5002 \
  -p 8080:8080 \
  ghcr.io/google/sam-node:latest \
  run --data-dir /data --bind-addr 0.0.0.0:8080 --api-token my-secret-token
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
