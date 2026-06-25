# Developer Guide & Repository Setup

This document is for developers who want to compile SAM from source, run a local development mesh, run the test suites, or contribute to the repository.

---

## Prerequisites

To build and test the Go binaries natively:

- **Go Toolchain**: Go 1.25+
- **Docker**: For running containerized integration tests and building local images.
- **BATS**: `bats-core` framework for running E2E shell tests.

---

## Build from Source

Clone the repository and compile the binaries:

```bash
git clone https://github.com/google/sam.git
cd sam
make build
```

This compiles and generates the following binaries under `./bin/`:

- `./bin/sam-hub`: The OIDC identity bridge and cryptographic Biscuit token issuer.
- `./bin/sam-node`: The mesh agent node CLI supporting `join` and `run` commands.
- `./bin/mcp-client`: A CLI-based utility to interact with MCP servers.

---

## Running a Local Dev Hub

To run `sam-hub` locally for testing, you must supply OIDC issuer configurations and a 32-byte hexadecimal seed key:

```bash
# Generate a random 32-byte key for biscuit signing
export SAM_HUB_KEY=$(openssl rand -hex 32)
export SAM_OIDC_ISSUER=https://issuer.example.com
export SAM_OIDC_ID=sam-client
export SAM_OIDC_SECRET=sam-secret

./bin/sam-hub
```

---

## Testing

The repository implements a testing pyramid. Ensure the test suites are green before pushing code:

### 1. Go Unit & Integration Tests
Runs the packages' unit tests and multi-node integration tests:
```bash
make test
```

### 2. Local E2E Tests (BATS)
Validates local command-line behaviors for `sam-node` and `sam-hub`:
```bash
make test-e2e
```

### 3. Containerized Mesh E2E (BATS)
Builds local Docker images, spins up a mock OIDC server, runs `sam-hub` and multiple `sam-node` containers in a local bridge network, and performs end-to-end device flows and tool discovery:
```bash
make test-e2e-container
```

---

## Local Kubernetes Test Setup

For end-to-end integration testing in a local Kubernetes environment:

1. **Start Kind Cluster**:
   Ensure you have a Kind cluster running.
2. **Build and Load Images**:
   ```bash
   make docker-build-node
   make docker-build-hub
   kind load docker-image sam-node:local
   kind load docker-image sam-hub:local
   ```
3. **Deploy Config Templates**:
   Deploy and template configuration files located under `.github/k8s/` or `development/kind/` to spin up local nodes and vLLM inference engines.
