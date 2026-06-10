# Quick Start

## Prerequisites

- Go toolchain
- Docker (for containerized e2e tests)
- BATS (`bats-core`)

## Build

```bash
git clone https://github.com/google/sam.git
cd sam
make build
```

This creates:

- `./bin/sam-hub`
- `./bin/sam-node`

## Start Hub

`sam-hub` requires OIDC issuer settings and a 32-byte hex key seed.

```bash
SAM_OIDC_ISSUER=https://issuer.example.com \
SAM_OIDC_ID=sam-client \
SAM_OIDC_SECRET=sam-secret \
SAM_HUB_KEY=$(openssl rand -hex 32) \
./bin/sam-hub
```

## Join Mesh (Enroll Node)

To register the node's cryptographic identity with the hub:

```bash
./bin/sam-node join http://localhost:8080
```

This initiates an interactive OIDC Device Authorization flow. It prints a verification URL for you to navigate to in your browser. Once authenticated, the hub registers your node ID and responds with the cryptographic Biscuit identity token. This token, along with the derived node private key and hub discovery addresses, is stored in your local data directory.

## Run Node

### Using Stored Identity

If the node has already joined a mesh, start it simply by running (note that `--api-token` is mandatory to protect the local API when not using mTLS):

```bash
./bin/sam-node run --api-token my-secret-token
```

This automatically loads the private key and authorized Biscuit token from the persistent local store.

### Using explicit OIDC Credentials

Alternatively, you can skip the manual `join` step and pass OIDC client credentials directly on startup so the node registers and enrolls dynamically:

```bash
./bin/sam-node run \
  --oidc-issuer https://issuer.example.com \
  --client-id <id> \
  --client-secret <secret> \
  --api-token my-secret-token
```

## Docker Quick Start

You can fully manage and run your SAM node using Docker. To persist the node identity, cryptographic keys, and peer authorization store, mount a local directory as a volume to the container.

### 1. Join the Mesh

Enroll your node interactively into the testnet mesh (e.g. `https://bananas.sam-mesh.dev`):

```bash
docker run -it \
  -v $(pwd)/sam-data:/data \
  ghcr.io/google/sam-node:latest \
  join --data-dir /data https://bananas.sam-mesh.dev
```

1. The CLI will output a Device Authorization URL.
2. Visit the URL in your browser to authenticate.
3. Upon successful login, the container will complete registration, save the credentials inside `/data/agent.db` (persisted at `./sam-data/agent.db` on your host), and terminate.

### 2. Run the Node

Start your node as a background container using the stored configuration and credentials. Make sure to bind the internal HTTP server to `0.0.0.0:8080` so that you can access the local MCP/Sidecar API from outside the container, publish the libp2p network ports, and set the required `--api-token` parameter:

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

## Test

```bash
make test
make test-e2e
make test-e2e-container
```

`make test-e2e-container` runs hub + multiple node containers with a mock OIDC provider.
