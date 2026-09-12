---
title: "Digital & Data Sovereignty"
linkTitle: "Sovereignty Architecture"
weight: 12
---

# Digital & Data Sovereignty in SAM

This document articulates the architecture, technical mechanisms, and legal-regulatory foundations of digital and data sovereignty in the **Sovereign Agent Mesh (SAM)**.

---

## 1. Core Distinctions: OSS Project vs. Products vs. Developer Testnets

To understand sovereignty in SAM, three fundamental distinctions must be established:

### 1.1 An Open-Source Software Project
SAM is an **open-source software project licensed under Apache-2.0**, developed in the open on [GitHub](https://github.com/google/sam). 
* It is **an open, decentralized networking protocol and runtime**, not a closed SaaS offering.
* It contains **no telemetry, no tracking, no phone-home mechanisms**, and no hardcoded dependencies on any proprietary model provider.
* Operators have the unfettered right to inspect, audit, compile, and deploy the entire software stack on any compute environment worldwide.

### 1.2 Public Developer Testnets Have Zero Sovereign Value
The public endpoints maintained by project contributors (`bananas.sam-mesh.dev` tracking `main` and `hub.sam-mesh.dev` tracking release tags) are **free, public developer testnets created using community resources**:
* **Purpose:** They exist strictly as ephemeral testing sandboxes for continuous integration (CI/CD), interoperability checks, and developer rapid prototyping.
* **Community-Funded with No Guarantees:** Public testnets are hosted using donated community resources and carry **no guarantees, no uptime commitments, and zero SLA**. They hold no production data, provide no persistent storage warranties, and are inherently non-sovereign because you are interacting with a shared developer testing environment. **A shared public testnet is, by definition, not sovereign.**

### 1.3 Sovereignty Through Architectural & Cryptographic Control
In SAM, digital sovereignty is built on verifiable architectural control: cryptographic key custody, independent identity federation, and strict data residency enforcement. To establish a sovereign deployment, an organization deploys its control plane (`sam-control-plane`), routing layer (`sam-router`), and nodes (`sam-node`) on dedicated infrastructure (such as on-premise datacenters, bare metal, air-gapped environments, or dedicated sovereign cloud infrastructure including Google Cloud with Customer-Managed Keys and regional data residency) using the provided [Helm chart](https://github.com/google/sam/tree/main/charts/sam-mesh) or [Kubernetes deployment guide](../user/kubernetes-deployment/).

---

## 2. Evaluation Against the Five Pillars of Sovereignty

Evaluating SAM in a dedicated sovereign deployment across the five industry-standard pillars of digital sovereignty:

| Pillar | How SAM Delivers Sovereignty | Regulatory & Standards Alignment |
| :--- | :--- | :--- |
| **01 · Territorial** | **Cryptographically Attested Egress Gates:** The data plane is direct P2P and end-to-end encrypted (relays carry only ciphertext). Attested label gates (`VerifyPeerLabels`) cryptographically guarantee that prompts, tools, and data never leave defined territorial or jurisdictional boundaries (e.g. `jurisdiction=eu`, `region=de-txl`). | **GDPR Chapter V (Arts. 44–49)** (Cross-border data transfers), **EU Cloud Sovereignty Framework (SEAL-3)** |
| **02 · Operational** | **Autonomous Key Custody & Local Veto:** The deploying organization generates and holds 100% of the root cryptographic signing keys. Local nodes enforce custom Datalog attenuation policies (`attenuation.checks`, `attenuation.policies`) that execute *before* control plane grants, providing an absolute local veto. | **NIS2 Directive**, **Zero Trust Architecture (NIST SP 800-207)** |
| **03 · Technological** | **100% Open Source & Uncooperative Sandbox Confinement:** Apache-2.0 license, built on open protocols (libp2p, Biscuit Datalog, MCP, standard OIDC). Agent sandboxes (`sam-box`, `nano-init`) run in `network=none` with structural route isolation, preventing leakage without relying on agent cooperation. | **EU Data Act**, **Open Source Initiative (OSI)** |
| **04 · Legal / Jurisdictional** | **Autonomous Cryptographic Custody:** By retaining complete custody of root signing keys (via local HSMs, KMS, or Cloud EKM) and identity infrastructure, all cryptographic material and data flows remain under the operator's direct jurisdiction and control, preventing unauthorized extraterritorial access. | **EU Data Protection Law**, **SecNumCloud / C5** |
| **05 · Financial** | **Zero Lock-In & Open Interoperability:** No license fees, no per-token meters, no proprietary runtime lock-in. Full portability across edge devices, local servers, and multi-cloud environments. | **EU Interoperability Framework (EIF)** |

---

## 3. Concrete Sovereign Acts & Technical Mechanisms

SAM implements specific, verifiable cryptographic and networking mechanisms designed to enforce data and execution sovereignty:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ CONSUMER NODE (Local Sovereign Boundary)                                               │
│                                                                                        │
│  1. Sandboxed Agent (network=none)                                                     │
│     └── Issues request: X-Sam-Required-Labels: jurisdiction=eu,compliance=gdpr         │
│                                                                                        │
│  2. Local sam-box / sidecar (Fail-Closed Egress Enforcement)                           │
│     └── Intercepts request before network transmission                                 │
│     └── Fetches candidate provider's Biscuit token                                     │
│     └── VerifyPeerLabels(): Cryptographically validates control-plane signature,       │
│         verifies peer ID binding, and evaluates attested label("jurisdiction", "eu")   │
│                                                                                        │
│     [ Verdict: PASS ] ────────────────────────────────────────────────────────┐        │
└───────────────────────────────────────────────────────────────────────────────┼────────┘
                                                                                │ P2P e2e
                                                                                │ encrypted
┌───────────────────────────────────────────────────────────────────────────────┼────────┐
│ PROVIDER NODE (Destination Sovereign Boundary)                                ▼        │
│                                                                                        │
│  3. Incoming Request Verification                                                      │
│     └── Authenticates caller Biscuit and token expiration                              │
│                                                                                        │
│  4. Local Attenuation Engine (Autonomous Local Veto)                                   │
│     └── Evaluates local attenuation rules BEFORE control plane grants                  │
│     └── E.g.: check if label("jurisdiction", "eu");                                    │
│               deny if client_origin("untrusted_zone");                                 │
│                                                                                        │
│  5. Execution in Local Sandbox                                                         │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Attested Labels Gate: Territorial & Jurisdictional Containment

In cross-border and multi-tenant agent networks, gossiped metadata cannot be trusted at face value. SAM implements a **fail-closed, cryptographic label gate**:
1. **Operator-Declared & Authority-Attested:** When a provider node enrolls, its declared labels (e.g. `jurisdiction=eu`, `region=de-west`, `compliance=hipaa`) are verified by the control plane against its role policy and minted into the token authority block as immutable `label(key, value)` Datalog facts (`api.FactLabel`).
2. **Consumer-Side Verification Before Egress:** When an agent or consumer specifies required labels (via the `X-Sam-Required-Labels` HTTP header or `call_remote_tool` parameters), `VerifyPeerLabels` fetches the provider's Biscuit, verifies the signature against the trusted control plane public key, verifies peer binding, and proves the existence of the required label facts **before any payload byte leaves the local machine**.
3. **Anti-Exfiltration Guarantee:** If a provider does not present a valid control-plane-signed Biscuit attesting to the required jurisdiction or security label, the connection is aborted immediately. Gossiped DHT records are only used for discovery ranking; they are never trusted for authorization.

### 3.2 Autonomous Local Veto: Destination-Side Attenuation

Under Zero Trust and operational sovereignty, a centralized control plane must never possess absolute power over local compute and data. 
* Local nodes configure an `attenuation` block containing local Datalog rules and policies.
* **Evaluation Order:** Local policies are evaluated **before** central control plane grants. Even if a central authority grants a remote agent access to a service (e.g. `mcp://*`), the destination node operator can unilaterally veto or restrict access using local rules:

```yaml
# Local node attenuation configuration (sam-node.yaml)
attenuation:
  rules:
    - 'time(2026-09-01T00:00:00Z) <- true;'
  policies:
    # Autonomous local veto: reject any caller not attested in the EU jurisdiction
    - 'deny if !label("jurisdiction", "eu");'
    - 'deny if user("revoked_contractor_id");'
```

### 3.3 Identity Evidence API: Independent Auditing Without Phone-Home

To comply with regulatory audit requirements (e.g., EU Cloud Sovereignty Framework SEAL-3, ISO 27001, SOC2), nodes expose local, cryptographically sealed evidence endpoints (`GET /sam/identity` and `GET /sam/peer/{peer_id}/evidence`):
* Allows auditors and local verification engines to inspect raw Biscuit tokens, SPKI DER public key certificates, role assignments, and attested labels.
* **Offline Verification:** Verification is mathematically self-contained using public-key cryptography; no live network calls or telemetry to external servers are required.

---

## 4. Addressing Zero-Trust Invariants vs. "Kill Switch" Misconceptions

In discussions of cryptographic networks, bounded credentials and revocation mechanisms are occasionally misunderstood. It is vital to clarify the cryptographic purpose of these invariants:

### 4.1 Bounded Token Expiration (TTL)
* **Cryptographic Rationale:** In Zero-Trust architectures, bearer credentials must have finite lifetimes (e.g. 24 hours). This mitigates the risk of replay attacks, stolen token persistence, and long-term key compromise. This is the same principle underlying **SPIFFE/SPIRE SVID rotation**, **OAuth 2.0 access token TTLs**, and **Kerberos ticket lifetimes**.
* **Operator Control:** In a dedicated sovereign control plane, the token lifetime, renewal interval, and grace periods are fully configured by the local administrator.
* **Fail-Closed Principle:** When a cryptographic credential expires and cannot be renewed (for instance, if the node has been decommissioned or network partitioned), the node daemon terminates its active mesh routes to prevent unauthorized, unauthenticated state persistence.

### 4.2 Cryptographic Revocation
* **Security Function:** Revocation (`/admin/revoke`) allows network administrators to instantly ban a compromised node or rogue agent from the mesh.
* **Sovereign Authority:** In a dedicated deployment, the revocation authority belongs exclusively to the organization deploying the control plane. Nobody outside that organization possesses root keys or revocation privileges.

---

## 5. Summary: The Sovereign Architecture Checklist

When deploying SAM for mission-critical, sovereign agent operations:

1. **Deploy Dedicated Control Plane Infrastructure:** Use the Helm chart or Kubernetes manifests to launch `sam-control-plane` on your chosen sovereign infrastructure (managed cloud with customer keys, private Kubernetes, or bare metal).
2. **Maintain Root Cryptographic Key Custody:** Generate, manage, and hold your own Ed25519 root signing keys (via KMS/Cloud EKM or HSMs).
3. **Use Your Own OIDC Identity Provider:** Point `--issuer` to your internal Keycloak, Dex, or corporate IdP.
4. **Declare & Attest Sovereignty Labels:** Declare `labels: {jurisdiction: eu, region: <your-region>}` in each node's `sam-node.yaml` and configure control plane roles with `allowed_labels`.
5. **Enforce Jurisdictional Egress:** Set `egress.require_labels` in `sam-node.yaml` (e.g. `jurisdiction: eu`) so every provider must attest the boundary before the node sends it anything. Agents may narrow further per request with `X-Sam-Required-Labels`, but cannot widen past the floor or waive it by omitting the header — the two are checked independently and every pair of the floor must hold.
6. **Set Local Attenuation Vetoes:** Configure local node `attenuation.policies` to retain final destination-side access control.
