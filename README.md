# SAM: Sovereign Agent Mesh

SAM is a zero-trust, pure P2P networking layer for autonomous agents.

It is built for environments where centralized gateways and centralized trust are a liability. Agents discover each other over libp2p DHT, authenticate with passport biscuits, authorize capabilities with Biscuit caveats, and communicate directly over A2A streams.

## Why SAM

- Pure P2P: no API gateway in the data path
- Zero-trust by default: every call is authenticated and authorized
- Isolated mesh namespace: separate SAM protocol space and storage scope
- Auditability: inspect tokens/cards and dry-run key flows

## Quick Start

### Build

```bash
make build
./bin/sam-agent --help
./bin/sam-hub --help
```

### Run tests

```bash
make test
make test-e2e
```

### First workflow

```bash
# Authenticate
sam-agent identity login --hub https://identity.example.com

# Publish an agent capability
sam-agent publish --skill risk-audit --mcp-port 8080

# Call by capability
sam-agent call risk-audit --message "audit this report"

# Inspect credential artifacts
sam-agent inspect biscuit "vendor-bot;allow_skill=risk-audit"
```

## Documentation

- Docs site: https://aojea.github.io/sam
- Manifesto: https://aojea.github.io/sam/#/README.md
- User journey (dark mesh): https://aojea.github.io/sam/#/guides/dark-mesh.md
- CLI reference: https://aojea.github.io/sam/#/cli/reference.md
- Testing guide: https://aojea.github.io/sam/#/testing.md

## Architecture

SAM keeps control at the edge: discovery is federated, trust is verified locally, and execution stays peer-to-peer.

```mermaid
flowchart LR
	A[Agent A / Caller] -->|Discover capability| DHT[(Federated DHT\n/sam/fed/<id>)]
	DHT -->|Peer candidates| A
	A -->|A2A stream + Vouch + Biscuit| B[Agent B / Callee]
	B -->|Federation Gate\nverify vouch + peer identity| G[AuthZ Layer]
	G -->|BiscuitSkillGate\nallow_skill(c)| E[MCP Resource / Skill]
	E -->|Result| B
	B -->|A2A response| A
```

Trust flow summary:

- Discovery: agents find peers by capability in an isolated federation namespace.
- Authentication: callee verifies caller identity with a locally trusted vouch.
- Authorization: Biscuit caveats constrain which capability can be executed.
- Execution: skill runs locally (for example via MCP) and response returns over A2A.

## Development

Key make targets:

- `make build`
- `make test`
- `make test-e2e`
- `make lint`

## License

See [LICENSE](LICENSE).

## Disclaimer

This is not an officially supported Google product. This project is not eligible
for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
