# FAQ: Frequently Asked Questions

## What is SAM?

SAM (Sovereign Agent Mesh) is a zero-trust networking layer for autonomous agents.
It provides peer discovery, identity verification, and capability authorization over pure libp2p.

## Getting Started

### How do I install SAM?

```bash
git clone https://github.com/aojea/sam.git
cd sam
make build
./bin/sam-agent --help
```

Requirements: Go 1.21+, Make, BATS (for E2E tests).

### How do I publish my first agent?

1. Authenticate with your hub:

```bash
sam-agent identity login --hub <your-hub-url>
```

2. Publish a local MCP capability:

```bash
sam-agent publish --skill mycapability --mcp-port 8080
```

### How do I call an agent?

```bash
sam-agent call mycapability --message "Do something"
```

## Core Concepts

### Do I need to manage federations manually?

No. SAM now runs with a single default federation namespace at runtime.
The old federation management CLI commands were removed.

### What is a passport biscuit?

A passport biscuit is the identity credential issued by the hub and bound to your peer identity.
It is used for authentication during peer establishment.

### What is a Biscuit token?

A Biscuit token grants capability-level authorization.
Example format:

`alice;allow_skill=weather-bot,risk-audit`

### What is an agent card?

A signed manifest published to the DHT containing peer id, skills, and resources.

## Architecture and Security

### Why peer-to-peer instead of a gateway?

P2P avoids centralized bottlenecks and trust chokepoints.
Peers communicate directly, and trust is cryptographic.

### Is SAM production-ready?

SAM is in active development. Core paths are tested, but you should apply standard production hardening:
- secure key storage
- short credential lifetimes
- monitoring and incident response

### How do I protect credentials?

- keep local config directory protected by OS permissions
- rotate hub credentials regularly
- inspect biscuits before sharing

## Networking

### Can SAM work behind NAT?

Yes. SAM relies on libp2p connectivity features including relay and hole punching.

### Can I run a node in the cloud?

Yes.

```bash
sam-agent up --listen /ip4/0.0.0.0/udp/4001/quic-v1
```

## Performance

### How many peers can it handle?

The practical limit depends on network and host resources.
For most deployments, discovery latency is dominated by DHT topology and cache warmth.

### How fast are calls?

Call latency is usually the sum of:
- discovery time (first lookup can be slower)
- connection establishment
- remote tool execution time

## Operations

### Where are credentials and state stored?

```text
~/.config/sam/
├── identity/
│   └── credentials.json
└── federations/
    └── default.db
```

### How do I back up local state?

```bash
cp ~/.config/sam/federations/default.db ~/backup/default.db.backup
cp -r ~/.config/sam/identity ~/backup/identity.backup
```

### How do I refresh identity credentials?

```bash
sam-agent identity login --hub <hub-url>
```

### How do I debug a failed call?

1. Confirm identity is present:

```bash
sam-agent identity whoami
```

2. Check visible agents:

```bash
sam-agent mesh get agents
```

3. Dry-run request:

```bash
sam-agent call mycapability --message "test" --dry-run=client
```

4. Increase logging:

```bash
SAM_DEBUG=1 sam-agent call mycapability --message "test"
```

## Integration

### Can I use SAM as a library?

Yes. Import SAM packages in Go and construct a node with `sam/pkg/net`.

### Can I run SAM in Docker/Kubernetes?

Yes. Persist `~/.config/sam` and expose libp2p ports as needed.

## Development

### How do I run tests?

```bash
go test -race ./...
make build
make test-e2e
```

### Where do I report bugs?

Open an issue at:
https://github.com/aojea/sam/issues
