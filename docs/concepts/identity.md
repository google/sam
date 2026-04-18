# Identity & Vouch System: Decentralized Credentials

## The Central Authority Problem

Traditional systems use a **central identity provider**:

```
All agents → OAuth/OIDC Server → Decide who is allowed

Issues:
1. The IdP must always be available (unavailable = no agents work)
2. The IdP sees all authentication attempts (privacy risk)
3. If compromised, all agents lose identity
4. Offline operation is impossible
```

SAM solves this with **vouch-based identity** that works offline.

---

## How Vouch-Based Identity Works

### Phase 1: Authentication (Online, One-Time)

```bash
sam identity login --hub https://identity.acme.corp --federation finance
```

**What happens:**

1. User provides username/password
2. SAM sends credentials to the hub
3. Hub verifies credentials (LDAP, database, whatever)
4. Hub issues a **Vouch** (signed JSON)
5. Vouch is cached locally in bbolt
6. Hub is no longer needed

**Vouch structure:**

```json
{
  "subject": "alice.smith@acme.corp",
  "peer_id": "12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK",
  "federation": "finance",
  "issued_at": "2026-04-18T10:00:00Z",
  "expires_at": "2027-04-18T10:00:00Z",
  "signature": "abcdef... (hub's Ed25519 signature)"
}
```

### Phase 2: Offline Authorization (No Server)

After login, Alice can operate completely offline:

```bash
# Alice publishes an agent (no network)
sam publish --federation finance --skill risk-audit --mcp-port 8080

# Alice calls another agent (peer-to-peer only)
sam call weather-bot --federation finance --message "forecast"
```

**Behind the scenes:**

1. Alice's agent sends the cached vouch to Bob's agent
2. Bob's agent:
   - Extracts the hub's public key from the vouch
   - Verifies the signature (locally, cryptographically)
   - Checks if the vouch is expired
   - If valid, trusts the vouch
3. No network request to the hub

**Trust chain:**

```
Hub issued vouch → Hub's signature on vouch
                         ↓
Alice's agent stores vouch in bbolt
                         ↓
Bob's agent receives vouch
                         ↓
Bob's agent verifies hub's signature (public key known)
                         ↓
Bob trusts Alice (because Bob trusts the hub)
```

---

## Why This Works Without a Central Authority

The key insight: **Trust the issuer's signature, not the current state of a server.**

### Traditional Approach (Stateful)
```
Agent A asks: "Is Alice still authorized?"
             ↓
IdP Server: "Let me check... yes, still authorized"
             ↓
Agent A trusts response

Problem: IdP must always have the answer
```

### SAM Approach (Cryptographic)
```
Agent A receives: "Alice issued by Hub on 2026-04-18, expires 2027-04-18, signed by Hub"
Agent A verifies: Hub's signature matches public key
             ↓
Agent A trusts vouch (if not expired)

Benefit: No server needed, offline works, Hub could disappear
```

---

## Vouch Expiry and Renewal

Vouches have a limited lifetime (typically 1 year):

```json
{
  "subject": "alice.smith",
  "issued_at": "2026-04-18T10:00:00Z",
  "expires_at": "2027-04-18T10:00:00Z"
}
```

When the vouch expires:

```bash
sam call risk-audit --federation finance --message "hello"
```

Error:
```
Error: stored identity vouch is expired; run login again
```

Re-authenticate:
```bash
sam identity login --hub https://identity.acme.corp --federation finance
```

SAM:
1. Contacts hub (online required for renewal)
2. Verifies credentials again
3. Gets new vouch
4. Caches it (good for another year)

---

## Vouch vs Token vs Signature

SAM uses three layers of cryptography:

### Layer 1: Vouch (Identity)
**Purpose:** Prove you are who you say you are

```
"Alice is alice.smith@acme.corp, issued by acme.corp hub on 2026-04-18"
(signed by hub)

Lifetime: 1 year
Usage: Authentication (am I in the federation?)
```

### Layer 2: Biscuit (Authorization)
**Purpose:** Prove you can do specific things

```
"alice;allow_skill=risk-audit,weather-bot"

Lifetime: Unlimited (or revoked by removing from app)
Usage: Authorization (what can I do?)
```

### Layer 3: Message Signature (Proof of Ownership)
**Purpose:** Prove you sent a specific message

```
Agent Card:
{
  "peer_id": "12D3Koo...",
  "agent_card": {...},
  "signature": "..." (signed with agent's Ed25519 key)
}

Lifetime: Single message
Usage: Proof (did this agent really send this?)
```

### Example Flow

```
1. Alice logs in
   └─ Gets vouch (identity layer)

2. Alice publishes agent
   └─ Signs Agent Card with Ed25519 key (proof layer)

3. Alice grants partner access
   └─ Creates Biscuit token (authorization layer)

4. Partner calls Alice's agent
   ├─ Sends vouch (authentication: "I'm in the federation")
   ├─ Sends Biscuit token (authorization: "I can use risk-audit")
   └─ Alice verifies both → executes
```

---

## Multi-Federation Identity

An agent can have vouches from multiple federations:

```bash
# Alice logs into finance federation
sam identity login --hub https://identity-finance.acme.corp --federation finance

# Alice logs into operations federation  
sam identity login --hub https://identity-ops.acme.corp --federation operations
```

Storage:

```
~/.config/sam/
├── federations/
│   ├── finance.db
│   │   └── vouches: {alice → {subject: alice, issued_at: ...}}
│   └── operations.db
│       └── vouches: {alice → {subject: alice, issued_at: ...}}
```

**Key:** Each vouch is federation-scoped, stored in that federation's database.

---

## The Hub: Simple Identity Server

The hub is **not** a gateway. It's a simple service that:

1. Verifies credentials (LDAP, OAuth, database, whatever)
2. Issues a signed vouch
3. Returns the vouch
4. Forgets the request (stateless)

### Hub Implementation (Pseudocode)

```go
type Hub struct {
    privateKey ed25519.PrivateKey
    credential_checker CredentialChecker  // LDAP, database, etc
}

func (h *Hub) Login(username, password string, federation string) (*Vouch, error) {
    // 1. Verify credentials
    if !h.credential_checker.Verify(username, password) {
        return nil, ErrInvalidCredentials
    }

    // 2. Generate PeerID from username (deterministic)
    peerID := DeterministicPeerID(username)

    // 3. Create vouch
    vouch := &Vouch{
        Subject: username,
        PeerID: peerID,
        Federation: federation,
        IssuedAt: time.Now(),
        ExpiresAt: time.Now().AddDate(1, 0, 0),
    }

    // 4. Sign it
    vouch.Signature = ed25519.Sign(h.privateKey, vouch.Bytes())

    // 5. Return (don't store)
    return vouch, nil
}
```

**Key properties:**
- **Stateless**: No database of issued vouches
- **Offline-capable**: Once issued, vouch works without the hub
- **Deterministic PeerID**: Same username always yields same PeerID

---

## Revocation: The Hard Problem

Traditional systems can revoke a credential instantly:

```
Hub: "User is revoked"
→ All agents reject user immediately
```

SAM cannot do this (no central authority), so:

### SAM Revocation Strategy

1. **Short vouch lifetime** (e.g., 1 year)
2. **Biscuit-level revocation** (delete token from app)
3. **Hub-side certificate pinning** (hub can rotate keys)

**Scenario: Alice's credential is compromised**

1. Acme Corp revokes Alice in their hub
2. Alice's existing vouch is still valid (until expiry)
3. Alice cannot login again (hub rejects credentials)
4. New vouches cannot be issued to Alice
5. Existing vouches eventually expire

**Mitigation:**
- Use short vouch lifetime (e.g., 3 months instead of 1 year)
- Implement hub-side key rotation (revoke all vouches by retiring keys)
- Use Biscuit token revocation at application level

---

## Hub Operator Trust Model

**SAM does NOT eliminate hub trust completely.** Here's why:

```
Issue: Who do you trust to verify credentials?

Option A: Acme Corp's hub (knows all of Acme's employees)
Option B: Certificate authority (verifies acme.corp domain)
Option C: Peer recommendation (other agents vouch for you)
```

**SAM supports all three:**

- **Option A** (Hub):
  ```bash
  sam identity login --hub https://identity.acme.corp --federation finance
  ```

- **Option B** (Certificate pinning):
  ```bash
  sam identity login --hub https://identity.acme.corp \
    --federation finance \
    --pin-certificate /path/to/cert.pem
  ```

- **Option C** (Peer vouching):
  ```bash
  sam vouch create alice \
    --subject alice.smith \
    --issued-by bob.jones
  ```

**The design principle:**
> Move as much trust as possible from *authorities* to *cryptography*.

---

## PeerID Derivation

Each agent has a **deterministic PeerID** derived from identity:

```go
// Traditional: Random PeerID
peerID := libp2p.NewRandomPeerID()  // 12D3KooXABC...

// SAM: Deterministic from identity
publicKey := DerivePublicKey("alice@acme.corp")
peerID := PeerIDFromPublicKey(publicKey)  // Always 12D3KooXABC...
```

**Benefits:**

1. **Reproducible**: Same identity always yields same PeerID
2. **Auditable**: Can verify identity from PeerID
3. **Lightweight**: No key management service needed

**How it works:**

```
Identity: "alice@acme.corp"
  ↓
SHA256 hash: "abc123..."
  ↓
Ed25519 key derivation: "abc123..." → PublicKey
  ↓
PeerID: libp2p.IDFromPublicKey(publicKey)
  ↓
Result: "12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK"
```

---

## Offline Workflow

After authentication, agents can work completely offline:

```bash
# Online: Alice logs in
sam identity login --hub https://identity.acme.corp --federation finance

# Offline: Publish agent
sam publish --federation finance --skill risk-audit --mcp-port 8080

# Offline: Call another agent (if both are in same LAN)
sam call bob.jones --federation finance --message "hello"

# Offline: Inspect credential
sam inspect biscuit "bob;allow_skill=risk-audit"
```

**No internet required** for any of these operations (after initial login).

---

## Summary: Identity Without Central Authority

| Aspect | Traditional | SAM |
|--------|-------------|-----|
| **Where identity is verified** | Central server (every time) | Local vouch (once) |
| **How trust is established** | Server state | Cryptographic signature |
| **Offline support** | No | Yes (after login) |
| **Revocation speed** | Instant | By vouch expiry |
| **Trust dependencies** | IdP must exist | Hub must exist at login time |
| **Federation support** | Single IdP | Multiple hubs per agent |

---

## Next Steps

- **[Biscuit Authorization](#/concepts/biscuit.md)**: How skill-based access control works
- **[Federation & Storage](#/concepts/federation.md)**: How federation isolation works
- **[A2A Protocol](#/concepts/a2a-protocol.md)**: How agents authenticate to each other
