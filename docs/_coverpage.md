![logo](data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text x=%225%22 y=%2280%22 font-size=%22120%22 fill=%22%236366f1%22>⚡</text></svg>)

# Sovereign Agent Mesh

> Zero-Trust Networking for the Agentic Era

- **Pure P2P**: No gateways, no central coordinators
- **Zero-Trust**: Cryptographic identity at the edge, not centralized authorities
- **Federation-Ready**: Isolated namespaces for enterprise dark meshes
- **Audit-First**: Built-in transparency for security compliance

[Documentation](#/README.md)
[GitHub](https://github.com/aojea/sam)
[Getting Started](#/quickstart.md)

---

## The Trust Desert Problem

In today's agentic systems, agents operate in a **trust desert**:

- **Gateways** become honeypots (central points of failure)
- **Centralized identity** providers can be breached or compromised
- **Network isolation** is difficult without expensive VPNs or custom infrastructure
- **Audit trails** are either missing or controlled by the infrastructure operator

SAM (Sovereign Agent Mesh) solves this by bringing **Zero-Trust principles to autonomous agents**.

## Engineering Truth

This is not marketing. SAM is built on proven principles:

1. **Cryptographic Identity**: Ed25519 keys derived from libp2p, not reliant on central authorities
2. **Federated DHT**: Isolated discovery namespaces (`/sam/fed/<id>`) prevent cross-federation discovery
3. **Identity Gating**: bbolt vouch database ensures peer identity before A2A handshake
4. **Skill-Based Authorization**: Biscuit tokens with caveats enforce fine-grained access control
5. **Transparent Auditing**: `sam inspect` and `--dry-run` modes expose all request/response shapes

No gateways. No magic. Just cryptography and networking.
