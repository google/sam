# Quick Start

## Prerequisites

- Go toolchain
- Docker (for containerized e2e tests)
- BATS (`bats-core`)

## Build

```bash
git clone https://github.com/aojea/sam.git
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

## Login Node

```bash
./bin/sam-node login --hub http://localhost:8080
```

The command prints a browser login URL and asks you to paste the identity biscuit token.

## Run Node

Using stored identity:

```bash
./bin/sam-node run
```

Or using explicit token:

```bash
./bin/sam-node run --token <identity-biscuit>
```

## Test

```bash
make test
make test-e2e
make test-e2e-container
```

`make test-e2e-container` runs hub + multiple node containers with a mock OIDC provider.
