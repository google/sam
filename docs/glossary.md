# Glossary

## A

**A2A**: Agent-to-Agent. RPC protocol for agents to call each other over libp2p streams.

**Agent**: An autonomous program that can publish skills to a federation and call skills offered by other agents.

**Agent Card**: Signed manifest published by an agent to the DHT, containing skills, resources, and signature.

**Authorization**: Determining what an authenticated agent is allowed to do (e.g., which skills it can invoke).

## B

**Biscuit**: Lightweight credential with caveats granting access to specific skills. Format: `subject;allow_skill=X,Y,Z`

**Blockade**: (Future) Mechanism to revoke agent identity in a federation.

**Bolt/bbolt**: Embedded key-value database used for federation storage. Pure Go, no external dependencies.

**Bootstrap**: Peer addresses used to join the DHT. Agents connect to bootstrap nodes to discover peers.

**Bytecode**: (Not used in SAM) Biscuit tokens are plain-text, not bytecode.

## C

**Capability**: Synonym for skill. The set of things an agent can do.

**Caveat**: Restriction in a Biscuit token (e.g., `allow_skill=X`).

**Certificate**: Cryptographic proof of identity, typically Ed25519 key.

**Cipher**: Encryption algorithm used in TLS transport (not user-facing in SAM).

**CLONE_NEWNET**: Linux namespace for network isolation in integration tests.

**Codec**: Encoder/decoder for serialization (JSON, bincode, etc.).

**Consensus**: SAM does NOT use consensus. Each federation manages independently.

**Cryptography**: Mathematical science for secure communication. SAM uses Ed25519 for signing and libp2p for TLS.

## D

**Dark Mesh**: Enterprise network where agents operate in isolation, not visible to the public mesh. Uses federation isolation.

**DCUtR**: Direct Connection UpgRade. libp2p mechanism for hole-punching through NAT.

**Delegation**: (Future) Allowing an agent to grant a subset of its skills to another agent.

**Device Flow**: OAuth-like authentication where a device opens a browser to authenticate (used by `sam identity login`).

**DHT**: Distributed Hash Table. Peer discovery mechanism used by libp2p. SAM scopes DHT announcements to federation namespaces.

**Dry-run**: Preview mode for commands. `--dry-run=client` builds locally, `--dry-run=server` skips final commit.

## E

**Ed25519**: Public-key cryptography algorithm for signing. Standard in libp2p.

**Economy**: Package in SAM for credentials, payments, and authorization.

**Endpoint**: URL where an MCP resource is available (e.g., `http://127.0.0.1:8080`).

**Enrollment**: Process of joining a federation (login + credential storage).

## F

**Federation**: Isolated P2P network where agents discover and call each other. Each federation has own DHT namespace and storage.

**Federation Gate**: Component that checks if a caller is in the federation (vouch verification).

**Federation ID**: Deterministic identifier for a federation, derived from name.

**Firewall**: Network filter. SAM uses libp2p's QUIC and WebSocket to traverse firewalls.

## G

**Gateway**: Central server that intermediates peer connections. SAM avoids gateways by using direct P2P.

**Governance**: Rules for a federation (who can join, which skills are allowed, etc.). SAM delegates to federation operators.

**gRPC**: RPC framework (not used in SAM; SAM uses libp2p streams + MCP).

## H

**Hub**: Identity server that issues vouches. Contacted once per login, then vouch is cached locally.

**Hole-Punch**: Technique for NAT traversal using ICE. libp2p DCUtR implements this.

**HSM**: Hardware Security Module for secure key storage.

## I

**Identity**: Proof of who you are. In SAM: cryptographic (Ed25519 key) + vouch.

**Identity Provider (IdP)**: Server that verifies credentials and issues tokens. SAM integrates with existing IdPs via hub.

**Isolation**: Separation of network namespaces to prevent cross-federation discovery.

## J

**JSON**: Serialization format used for Agent Cards, calls, and CLI output.

## K

**Key**: Cryptographic secret (Ed25519 private key). Stored in `~/.config/sam/identity/keystore.json`.

**Keyring**: Encrypted credential storage on OS (macOS Keychain, Linux Secret Service, Windows Credential Manager).

## L

**libp2p**: Modular P2P networking library used for connectivity, DHT, and relays. The foundation of SAM.

**Linux Namespace**: OS-level isolation for network, filesystem, etc. Used in integration tests.

**Listen Address**: Multiaddr where a node listens for connections (e.g., `/ip4/0.0.0.0/tcp/4001`).

## M

**Mesh**: Network of interconnected agents. SAM enables zero-trust meshes.

**MCP**: Model Context Protocol. Protocol for agents to define resources and capabilities.

**Middleware**: Component that processes requests/responses (e.g., `BiscuitSkillGate`).

**Micropayment**: Small payment sent with A2A call. Currently placeholder, future feature.

**Multiaddr**: Multi-protocol address format used by libp2p (e.g., `/ip4/127.0.0.1/tcp/8080`).

## N

**NAT**: Network Address Translation. Makes direct connections difficult. libp2p uses relays and hole-punching to overcome.

**Namespace**: DHT protocol prefix for scoping discovery (e.g., `/sam/fed/finance`).

**Nonce**: Number used once, for security. Used in micropayments to prevent replay.

## O

**OAuth/OIDC**: Standard authentication protocols. SAM doesn't use these; instead uses vouches.

**Offline**: Mode where SAM operates without network connectivity (possible with cached vouches).

**Operator**: Person or organization running a federation hub or node.

## P

**Peer**: Node in the P2P network identified by PeerID.

**PeerID**: Unique identifier for a libp2p node, derived from its Ed25519 public key.

**Peering**: Process of connecting two nodes directly.

**Permission**: Synonym for capability/skill.

**Private Key**: Secret cryptographic key used for signing. Never shared.

**Protocol**: Set of rules for communication. SAM defines `/sam/a2a/1.0` for agent calls.

**Proxy**: Intermediary that relays traffic. SAM avoids proxies where possible, uses libp2p relays as fallback.

**Public Key**: Cryptographic key that anyone can see. Used to verify signatures.

## Q

**QUIC**: UDP-based protocol often more lenient through firewalls than TCP.

## R

**Reputation**: System for tracking agent trustworthiness (future feature).

**Revocation**: Disabling a credential (vouch or Biscuit). SAM revokes by expiry or manual deletion.

**Relay**: Node that forwards traffic between peers that cannot connect directly.

## S

**SAM**: Sovereign Agent Mesh. Zero-trust P2P networking for agents.

**Schema**: Structure definition (e.g., Agent Card schema, vouch schema).

**Secret**: Sensitive data (private keys, credentials). Always protected.

**Signature**: Cryptographic proof that something was signed by a key. Ed25519 signatures in SAM.

**Skill**: Capability offered by an agent (e.g., "weather-bot", "risk-audit").

**Sovereign**: Having control over one's own identity and operations (not delegated to a central authority).

**Stream**: Bidirectional connection over libp2p for A2A communication.

**Subject**: Entity that holds a credential (username, email, etc.).

## T

**Token**: Credential granted to an agent. In SAM: vouch (identity) or Biscuit (authorization).

**TLS**: Transport Layer Security. Encryption used by libp2p for all connections.

**Timeout**: Maximum time to wait for an operation.

**Trust Desert**: Problem where agents operate without trust, in systems with central gatekeepers.

**Trustworthy**: An agent with good reputation (future feature).

## U

**UID**: User ID, usually a number (not used in SAM; uses usernames/emails).

**UUID**: Universally Unique Identifier. SAM derives deterministic IDs from usernames.

**Unencrypted**: Not encrypted. SAM never sends unencrypted credentials (uses TLS).

## V

**Voucher**: Component that manages vouch lifecycle.

**Vouch**: Cryptographic credential proving membership in a federation. Issued by hub, cached locally.

**Verify**: Cryptographic check that something is valid (signature, expiry, etc.).

## W

**Whitelist**: List of allowed peers or skills. SAM uses Biscuit caveats for skill whitelists.

**WebSocket**: Protocol for connections over HTTP. Used by libp2p for firewall traversal.

## X

**X.509**: Standard for digital certificates (not used in SAM; uses Ed25519 keys).

## Y

**YAML**: Configuration format (not used in SAM; uses CLI flags and JSON).

## Z

**Zero-Trust**: Security model where no entity is trusted by default. Everything must prove legitimacy. SAM's core philosophy.

---

## Acronyms Quick Reference

| Acronym | Full Name |
|---------|-----------|
| A2A | Agent-to-Agent |
| BATS | Bash Automated Testing System |
| DCUtR | Direct Connection UpgRade |
| DHT | Distributed Hash Table |
| Ed25519 | Elliptic Curve Signature Scheme |
| GOPATH | Go Package Path |
| gRPC | Google Remote Procedure Call |
| HSM | Hardware Security Module |
| ICE | Interactive Connectivity Establishment |
| IdP | Identity Provider |
| JSON | JavaScript Object Notation |
| KMS | Key Management Service |
| LDAP | Lightweight Directory Access Protocol |
| MCP | Model Context Protocol |
| NAT | Network Address Translation |
| OIDC | OpenID Connect |
| P2P | Peer-to-Peer |
| PeerID | Peer Identifier |
| QUIC | Quick UDP Internet Connection |
| RPC | Remote Procedure Call |
| SAM | Sovereign Agent Mesh |
| TLS | Transport Layer Security |
| UUID | Universally Unique Identifier |

---

## See Also

- **[Concepts](#/concepts/federation.md)**: Technical deep dives
- **[FAQ](#/faq.md)**: Common questions answered
- **[CLI Reference](#/cli/reference.md)**: Command documentation
