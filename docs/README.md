# Sovereign Agent Mesh: The Manifesto

## What is SAM?

**Sovereign Agent Mesh (SAM)** is a **zero-trust networking layer for autonomous agents**. It enables agents to discover, authenticate, and collaborate with each other—without centralized gateways, identity providers, or trust intermediaries.

SAM is built on two core principles:

1. **Pure P2P Architecture**: No gateways. Agents communicate directly using libp2p, with routing through DHT and relays.
2. **Zero-Trust at the Edge**: Cryptographic identity is verified locally, not delegated to a central authority.

## The Trust Desert Problem

Today's agentic systems operate in a **trust desert**:

### The Gateway Trap
- Agents talk to a central API gateway, which becomes a **single point of failure**
- The gateway sees all traffic (privacy nightmare)
- If the gateway is compromised, all agents are compromised
- Scaling requires more gateways (distributed trust problem unsolved)

### The Identity Provider Trap
- Agents rely on a central identity provider for credentials
- If the IdP is breached, all agents lose their identity
- The IdP becomes a **trusted third party** that must always be trusted
- Offline operation is impossible

### The Audit Nightmare
- Audit trails are controlled by the infrastructure operator
- No transparency into what data is flowing where
- Security teams have to trust the operator's logs
- Compliance becomes a matter of faith, not engineering

## How SAM Solves This

### 1. Pure P2P (No Gateways)
```
Traditional:  Agent A → Gateway → Agent B
SAM:          Agent A ↔ Agent B (direct, with DHT discovery)
```

Agents discover each other through a **federated DHT**:
- Discovery happens via `/sam` namespace (public) or `/sam/fed/<id>` (isolated)
- Connections are direct (or relayed through libp2p DCUtR if NAT'd)
- The DHT is the *only* intermediate—and it's read-only for discovery

### 2. Zero-Trust Identity (No Central Authority)
```
Traditional:  Agent A requests token from IdP → IdP validates → Agent A uses token
SAM:          Agent A proves identity via Ed25519 vouch → Agent B verifies locally
```

Every agent has a **cryptographic identity**:
- Ed25519 keypair (libp2p standard)
- Vouch from a federation (stored in bbolt, not fetched from a server)
- Peer ID derived directly from the key (no token, no revocation server)

Agent B verifies Agent A's identity by:
1. Checking if Agent A's Peer ID is in the federation's vouch database
2. Verifying the signature on the A2A message matches the Peer ID
3. No external lookup required

### 3. Federation Isolation (Enterprise Dark Mesh)
Enterprises often need **isolated networks** with their own governance rules:

```
Federation Alpha:  Agents operate in /sam/fed/alpha namespace
Federation Beta:   Agents operate in /sam/fed/beta namespace
Public Mesh:       Agents operate in /sam namespace

Result: Agents in Alpha cannot discover agents in Beta (network isolation)
```

Isolation is enforced at the DHT level:
- Each federation has its own `dht.ProtocolPrefix("/sam/fed/<id>")`
- A2A gating checks federation membership before handshake
- Storage is federated (one bbolt database per federation)

### 4. Skill-Based Authorization (Zero-Trust for Capabilities)
Even within a federation, not all agents can access all skills:

```
Alice publishes a Biscuit token:  "bob;allow_skill=weather-bot,chat"
Alice calls Bob with the token:   Bob verifies "weather-bot" is in allowed_skills
Result:                           Bob rejects any other capability
```

Biscuit tokens are lightweight caveats:
- Format: `<subject>;<caveat>=<value>`
- Parsed and validated locally (no external verification)
- Example: `alice;allow_skill=risk-audit,email-send`

### 5. Audit Transparency (sam inspect & --dry-run)
Every operation can be audited **before** it executes:

```bash
# Inspect a Biscuit token
sam inspect biscuit "alice;allow_skill=weather-bot"

# Preview an Agent Card without publishing
sam publish --skill weather-bot --mcp-port 8080 --dry-run=client

# Validate a call request without network
sam call bob --message "hello" --dry-run=client

# Decode an Agent Card JSON
sam inspect card '{"peer_id":"...", ...}'
```

All request/response shapes are exposed for security auditing.

## Architecture at a Glance

### Components

| Component | Purpose | Tech |
|-----------|---------|------|
| **libp2p Node** | P2P networking, DHT, relays | libp2p-go |
| **Federated DHT** | Isolated discovery per federation | dht.ProtocolPrefix |
| **bbolt Storage** | Distributed, consensus-free vouch DB | go.etcd.io/bbolt |
| **A2A Service** | Agent-to-agent RPC over libp2p streams | /sam/a2a/1.0 |
| **Federation Gate** | Identity verification before A2A | VouchGate |
| **Biscuit Gate** | Skill-based authorization | BiscuitSkillGate |
| **Discovery Service** | Capability-based peer lookup | DiscoveryService |
| **Agent Card** | Signed manifest of agent capabilities | protocol.AgentCard |

### Data Flow: A2A Call

```
Agent A                          DHT (Discovery)               Agent B
  │                                 │                             │
  ├─ sam call weather-bot           │                             │
  ├─ Discover peers for capability──┼──→ /sam/fed/alpha           │
  ├─ Select Agent B                 ← ──────────────────────────  │
  │                                                                │
  ├─ Connect to Agent B on /sam/a2a/1.0 ─────────────────────────→│
  │                                                                │
  ├─ Send Vouch + Biscuit ──────────────────────────────────────→│ FederationGate
  │                                                                ├─ Check vouch
  ├─ Send A2A request ──────────────────────────────────────────→│ BiscuitGate
  │                                                                ├─ Verify skill
  │                                 ← ── MCP Response ────────────┤ Execute
  │                                                                │
  └─ Return result to CLI                                          │
```

## Why "Sovereign"?

An agent is **sovereign** when it:
- Controls its own identity (not assigned by a central authority)
- Can operate without external services (no IdP, no gateway)
- Can form agreements with other agents (federation, vouches)
- Can prove its capabilities cryptographically (Agent Card, Biscuit)

SAM enables this sovereignty by moving trust from **authorities** to **cryptography**.

## What SAM Does NOT Do

- **SAM is not a blockchain**: No distributed consensus, no ledger
- **SAM is not a service mesh sidecar**: Agents link SAM directly, not via a sidecar
- **SAM is not OAuth/OIDC**: No tokens issued by a central authority
- **SAM is not a VPN**: No tunnel mode, direct P2P connections
- **SAM is not a replacement for TLS**: We use TLS for transport, libp2p handles the rest

## Next Steps

- **[Getting Started](#/guides/dark-mesh.md)**: Set up an enterprise dark mesh
- **[CLI Reference](#/cli/reference.md)**: Full kubectl-style command hierarchy
- **[Technical Deep Dive](#/concepts/federation.md)**: How federation isolation works
- **[Testing Guide](#/testing.md)**: Run the test suite locally

## Philosophy

SAM is built on **engineering truth**, not marketing claims:

- We show how the system works, not hide complexity
- We expose request/response shapes for auditing
- We use standard crypto (Ed25519, libp2p) not custom protocols
- We measure performance (not claim it)
- We test everything (unit, integration, E2E)

The goal is **trustworthy systems**, not trust-based systems.
