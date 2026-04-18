# FAQ: Frequently Asked Questions

## What is SAM?

**SAM (Sovereign Agent Mesh)** is a zero-trust networking layer for autonomous agents. It enables agents to discover, authenticate, and collaborate with each other without centralized gateways, identity providers, or trust intermediaries.

In short: **Pure P2P networks for agents, with cryptographic identity**.

---

## Getting Started

### How do I install SAM?

```bash
git clone https://github.com/your-org/sam.git
cd sam
make build
./bin/sam --help
```

Requirements: Go 1.21+, Make, BATS (for E2E tests)

### How do I publish my first agent?

1. Create a federation:
   ```bash
   sam mesh federations create mynet
   ```

2. Authenticate:
   ```bash
   sam identity login --hub <your-hub-url> --federation mynet
   ```

3. Publish the agent:
   ```bash
   sam publish --federation mynet --skill mycapability --mcp-port 8080
   ```

### How do I call an agent?

```bash
sam call mycapability --federation mynet --message "Do something"
```

See [User Journey Guide](/guides/dark-mesh.md) for a full walkthrough.

---

## Core Concepts

### What's a Federation?

A federation is an **isolated P2P network** where agents can discover and call each other.

- Each federation has its own DHT namespace (`/sam/fed/<id>`)
- Agents in one federation cannot discover agents in another
- Perfect for enterprise "dark meshes" (isolated networks)

### What's a Vouch?

A **vouch** is a cryptographic credential proving your identity to a federation.

- Issued once by an identity hub
- Cached locally (hub not needed after login)
- Includes your subject (username), PeerID, and expiry
- Signed by the hub (so we trust the issuer, not a server)

See [Identity & Vouch System](/concepts/identity.md).

### What's a Biscuit?

A **Biscuit** is a lightweight credential that grants access to specific skills.

Format: `alice;allow_skill=weather-bot,risk-audit`

- Restricts which skills a caller can invoke
- No central revocation (revoke by deleting locally)
- Plain-text for transparency

See [Biscuit Authorization](/concepts/biscuit.md).

### What's an Agent Card?

An **Agent Card** is a signed manifest published to the DHT.

Contains:
- Peer ID
- Skills (capabilities) offered
- MCP resources
- Ed25519 signature

Other agents use cards to verify which skills are available.

### What's A2A?

**Agent-to-Agent (A2A)** communication is the RPC protocol agents use to call each other.

- Runs over libp2p streams
- Includes vouch authentication and Biscuit authorization
- MCP-compatible (can call MCP servers)

---

## Architecture & Design

### Why "Sovereign"?

An agent is sovereign when it:
- Controls its own identity (not assigned by a central authority)
- Can operate without external services
- Can form agreements with other agents
- Proves capabilities cryptographically

### Why P2P instead of a gateway?

**Problems with gateways:**
- Single point of failure
- Privacy nightmare (sees all traffic)
- Requires trust in operator
- Bottleneck for scaling

**SAM's P2P approach:**
- Direct agent-to-agent connections
- No intermediary sees traffic
- Trust is cryptographic, not delegated
- Scales horizontally

### Why not use OAuth/OIDC?

**OAuth/OIDC issues in agent systems:**
- Require a token server (external dependency)
- Hard to revoke tokens at scale
- Token rotation is complex
- Don't map well to peer identity

**SAM's vouch approach:**
- Crypto-based, works offline
- Revoke by expiry or hub key rotation
- Simple caching strategy
- Peer identity is the public key

### Why plain-text Biscuits?

**Cryptographic Biscuits would require:**
- Central signature server (defeats the purpose)
- More computation
- Complex revocation

**Plain-text Biscuits:**
- Transparent (anyone can read permissions)
- Auditable (no decryption needed)
- Lightweight
- Simple revocation (delete locally)

Trade-off: Client can modify, but assumed to be trusted (OS isolation).

---

## Network & Connectivity

### Do agents need to be on the same network?

No. SAM uses libp2p's **relay** and **DCUtR** (hole-punching) to connect through NAT.

If direct connection fails:
1. Attempt hole-punch (DCUtR)
2. Fall back to relay
3. Communication works either way

See [CUJ-2 Test](/tests/integration/cuj_test.go) for example.

### Can I run a SAM node in the cloud?

Yes. A SAM node can:
- Run on a cloud VM
- Act as a relay for local agents
- Bootstrap peers into the DHT
- Provide gateway-like services (if you want)

```bash
sam up \
  --federation mynet \
  --listen /ip4/0.0.0.0/tcp/4001
```

### What about firewall/proxy?

SAM uses libp2p's connectivity features:
- **QUIC**: UDP (often more lenient than TCP)
- **WebSocket**: Works through HTTP proxies
- **Relay**: Falls back if direct connection fails

Most networks work out of the box.

---

## Security & Trust

### Is SAM production-ready?

SAM is in **active development**. Use in production with caution:
- ✅ Core functionality tested (unit + integration)
- ✅ E2E CLI tests passing
- ⚠️ Not yet audited by third-party security researchers
- ⚠️ Biscuit revocation is manual (no auto-expiry caveats yet)

### How do I protect against token leaks?

**Plain-text tokens can be modified by the client**, so:
1. Assume client OS is secure (standard assumption)
2. Use short token lifetimes (revoke often)
3. Don't put secrets in tokens (they're read-only caveats)
4. Monitor for suspicious activity

Better: Use cryptographic Biscuits (future feature).

### Can SAM be used for financial transactions?

**Not yet.** SAM currently supports:
- Authentication (who are you?)
- Authorization (what can you do?)

But does NOT provide:
- Accounting (what have you done?)
- Reputation (trustworthiness score)
- Dispute resolution

Use SAM + a financial ledger (blockchain, database) for transactions.

### What about key management?

SAM stores keys locally:
- **Private key**: `~/.config/sam/identity/keystore.json`
- **Protect with OS permissions**: `chmod 600 keystore.json`
- **Backup encrypted**: Use a password manager or encrypted backup

For production:
- Use HSM (Hardware Security Module)
- Use cloud KMS (AWS KMS, Google Cloud KMS)
- Future: SAM will support external key stores

---

## Performance

### How many peers can I have in a federation?

The DHT can handle **thousands of peers** per federation.

Tested scenarios:
- 10+ agents in a federation
- Multiple federations (100+ total agents)
- Peer discovery < 5 seconds (usually < 1 second)

Bottlenecks:
- Local machine resources (CPU, memory, disk)
- Network bandwidth (DHT discovery = peer list lookups)

### How fast are A2A calls?

Latency depends on:
- **Network latency**: ~10-100ms for local LAN
- **DHT discovery**: ~500ms-5s (cached after first call)
- **MCP execution**: Depends on your implementation

Example:
```
sam call weather-bot --message "forecast"
  Discovery: 1.2s
  A2A setup: 0.3s
  MCP call: 2.1s
  Total: 3.6s
```

### Can I scale to millions of agents?

**SAM is federated by design**, so:
- 100 small federations = scales better than 1 huge federation
- Each federation can be geographically isolated
- Federations can be run independently

But a single federation has limits:
- DHT bandwidth scales with peer count
- Storage grows linearly

**Recommendation**: Use multiple federations if > 10,000 agents.

---

## Operational & Troubleshooting

### Where are my credentials stored?

```
~/.config/sam/
├── identity/
│   ├── keystore.json      (private key)
│   ├── vouch.json         (federation vouch)
│   └── credentials.keyring (encrypted passwords, OS-specific)
└── federations/
    ├── finance.db         (bbolt database)
    ├── operations.db      (bbolt database)
    └── ...
```

All stored locally, not on a server.

### How do I back up my federation?

```bash
# Backup federation DB
cp ~/.config/sam/federations/<name>.db ~/backup/<name>.db.backup

# Backup identity
cp -r ~/.config/sam/identity ~/backup/identity.backup
```

To restore:
```bash
cp ~/backup/<name>.db.backup ~/.config/sam/federations/<name>.db
```

### My vouch expired. What do I do?

```bash
sam identity login --hub <hub-url> --federation <name>
```

Re-authenticate to get a new vouch (good for another year).

### sam inspect commands output is truncated. How do I see the full output?

```bash
# Pipe to less
sam inspect card '...' | less

# Save to file
sam inspect card '...' > card.txt
cat card.txt
```

### How do I debug a failed A2A call?

1. **Check federation exists**:
   ```bash
   sam mesh federations list --federation mynet
   ```

2. **Verify vouch is valid**:
   ```bash
   sam identity whoami --federation mynet
   ```

3. **Check peers in federation**:
   ```bash
   sam mesh get agents --federation mynet
   ```

4. **Dry-run the call**:
   ```bash
   sam call mycapability --federation mynet --message "test" --dry-run=client
   ```

5. **Check network connectivity**:
   ```bash
   sam up --federation mynet --listen /ip4/0.0.0.0/tcp/4001 --run-for 30s
   ```

6. **Enable debug logging**:
   ```bash
   SAM_DEBUG=1 sam call mycapability --federation mynet --message "test"
   ```

---

## Integration

### How do I integrate SAM with my app?

SAM is **library-friendly**:

```go
package main

import (
    "context"
    samnet "sam/pkg/net"
)

func main() {
    // Create a node
    node := samnet.NewNode(samnet.WithFederation("mynet"))
    defer node.Stop(context.Background())

    // Start listening
    if err := node.Start(context.Background()); err != nil {
        panic(err)
    }

    // Use the node...
}
```

### Can I use SAM without the CLI?

Yes. Import SAM as a Go library:

```bash
go get github.com/your-org/sam
```

See [pkg/net](/pkg/net), [pkg/protocol](/pkg/protocol), [pkg/economy](/pkg/economy).

### Can I use SAM with Docker/Kubernetes?

Yes. SAM can run as a sidecar or as a standalone service:

```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o sam ./cmd/sam
CMD ["./sam", "up", "--federation", "docker"]
```

For Kubernetes: Mount `~/.config/sam` as a persistent volume.

---

## Contributing & Development

### How do I contribute?

See [Contributing Guide](/contributing.md).

In short:
1. Fork the repo
2. Create a feature branch
3. Add tests
4. Open a PR

### How do I run tests locally?

```bash
# Unit + Integration
go test -race ./...

# E2E
make build
make test-e2e

# All
make test
```

### How do I report a bug?

Open an issue on GitHub with:
1. Expected behavior
2. Actual behavior
3. Steps to reproduce
4. Environment (Go version, OS)
5. Logs/error messages

---

## Roadmap & Future Work

### What's planned?

Short term:
- [ ] Cryptographic Biscuits (signed by issuer)
- [ ] Biscuit expiry caveats
- [ ] Hub API reference implementation
- [ ] Reputation system

Medium term:
- [ ] Payment channels (for micropayments)
- [ ] Cross-federation bridges
- [ ] Web UI for federation management
- [ ] Mobile SDK

Long term:
- [ ] SAM standardization (IETF draft)
- [ ] Interoperability with other meshes
- [ ] Blockchain integration (optional)

### How can I influence the roadmap?

Open an issue describing your use case. We prioritize based on:
1. Number of users affected
2. Alignment with SAM principles (zero-trust, P2P)
3. Feasibility given resources

---

## Licensing & Legal

### What license is SAM under?

[Check LICENSE file](https://github.com/your-org/sam/blob/main/LICENSE)

Typically: MIT or Apache 2.0

### Can I use SAM in my commercial product?

Yes, as long as you comply with the license (usually MIT/Apache means you can).

### Do I need to contribute back to SAM?

Not required, but appreciated. See [Contributing Guide](/contributing.md).

---

## More Questions?

- **Documentation**: https://docs.sam.dev
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions (if enabled)
- **Community**: (Slack/Discord if applicable)

Happy meshing! 🚀
