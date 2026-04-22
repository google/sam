# Federation & Storage: Physical Isolation

## The Problem: Shared Trust Infrastructure

Traditional agent systems use a **single central database**:

```
Gateway/Database
├── Org A agents
├── Org B agents
└── Org C agents

Issue: All organizations trust the same infrastructure operator.
Risk: If the database is breached, all organizations are compromised.
```

SAM solves this with **federated, isolated storage**.

---

## The Solution: bbolt per Federation

Each federation has its own **independent database**:

```
Finance Federation                Operations Federation
~/.config/sam/federations/        ~/.config/sam/federations/
  └── finance.db                    └── operations.db
      ├── identities                  ├── identities
      ├── vouches                     ├── vouches
      ├── reputation                  ├── reputation
      └── cache                       └── cache
```

**Key benefits:**

1. **Physical separation**: Data is not shared between federations
2. **Independent backups**: Each federation can back up its own DB
3. **Compliance isolation**: Finance data never touches Operations storage
4. **No trusted intermediary**: Each federation manages its own identities

---

## How Federation Storage Works

### Storage Layout

```
~/.config/sam/
├── identity/
│   ├── keystore.json          (personal Ed25519 key)
│   ├── vouch.json             (cached vouch from hub)
│   └── credentials.keyring    (encrypted passwords)
│
└── federations/
    ├── finance.db             (bbolt database)
    ├── operations.db          (bbolt database)
    └── public.db              (default federation)
```

### bbolt Structure (per federation)

Each `.db` file is a bbolt database with buckets:

```
finance.db
├── identities
│   ├── alice.smith → {peerID, created, updated}
│   ├── bob.jones   → {peerID, created, updated}
│   └── ...
│
├── vouches
│   ├── 12D3KooXA7cB... → {subject, federation, issued, expires}
│   ├── 12D3KooXdef456... → {subject, federation, issued, expires}
│   └── ...
│
├── reputation
│   ├── alice.smith → {trust_score, calls_completed, failed}
│   └── ...
│
└── cache
    ├── peer_addrs
    ├── capability_index
    └── ...
```

**Bucket purposes:**

| Bucket | Purpose | Example |
|--------|---------|---------|
| `identities` | Map subjects to PeerIDs | alice.smith → 12D3Koo... |
| `vouches` | Cached vouch credentials | 12D3Koo... → {issued, expires, federation} |
| `reputation` | Trust scores and call history | alice.smith → {score: 95, calls: 42} |
| `cache` | Temporary peer addresses, capability index | weather-bot → [12D3Koo..., 12D3Koo...] |

---

## Federation Initialization

When you create a federation:

```bash
sam-agent up
```

SAM:
1. Generates a deterministic federation ID from the name: `fed-abc123...` (sha256 of "finance")
2. Creates `~/.config/sam/federations/finance.db`
3. Initializes buckets: `identities`, `vouches`, `reputation`, `cache`
4. Stores federation metadata (name, ID, created_at)

```
$ cat ~/.config/sam/federations/finance.db
  (binary bbolt file)
```

The federation ID is deterministic, so re-creating a federation with the same name yields the same ID (useful for recovery).

---

## Identity Vouch System

When an agent authenticates with a federation hub:

```bash
sam-agent identity login --hub https://identity.acme.corp
```

### Step 1: Hub Issues Vouch

The hub (identity server) issues a signed voucher:

```json
{
  "subject": "alice.smith@acme.corp",
  "federation": "finance",
  "peer_id": "12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK",
  "issued_at": "2026-04-18T10:00:00Z",
  "expires_at": "2027-04-18T10:00:00Z",
  "signature": "..."  (hub's Ed25519 signature)
}
```

### Step 2: Local Cache

SAM stores the vouch in bbolt:

```
finance.db/vouches/12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK → {
  subject: "alice.smith@acme.corp",
  federation: "finance",
  issued_at: 2026-04-18T10:00:00Z,
  expires_at: 2027-04-18T10:00:00Z
}
```

### Step 3: Verification Without Server

When alice.smith publishes an agent or calls another agent, SAM:

1. Extracts the vouch from bbolt (no server needed)
2. Verifies the signature using the hub's public key (cached locally)
3. Checks expiry: is `now < expires_at`?
4. Allows the operation if valid

**Key insight:** The hub is **only contacted once** (at login). All subsequent operations use the cached vouch.

---

## Why No Central Database?

### Traditional Approach (Honeypot)
```
All agents → Central DB ← Security team

Issue 1: If DB is breached, all agents are compromised
Issue 2: DB operator must be trusted forever
Issue 3: Scaling requires replicating the trust
```

### SAM Approach (Federated)
```
Finance agents → Finance.db (Finance org controls)
Operations agents → Operations.db (Ops org controls)
Partner agents → Partner.db (Partner org controls)

Benefit 1: Finance breach doesn't expose Operations
Benefit 2: Each org controls its own trust
Benefit 3: Federations can operate independently
```

---

## Federation Isolation at DHT Level

Storage is isolated, and **DHT discovery is also isolated**:

### Finance Federation
```bash
sam-agent publish --skill risk-audit --mcp-port 8080
```

DHT announcement:
```
Namespace: /sam/fed/finance
PeerID: 12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK
Skill: risk-audit
```

### Operations Federation
```bash
sam-agent publish --skill incident-response --mcp-port 8090
```

DHT announcement:
```
Namespace: /sam/fed/operations
PeerID: 12D3KooXdef456...
Skill: incident-response
```

### Discovery Results

Finance agent queries:
```bash
sam-agent call risk-audit
```

Result: Finds only agents in `/sam/fed/finance` (risk-audit skill)

Operations agent queries:
```bash
sam-agent call risk-audit
```

Result: Finds nothing (risk-audit not published in operations namespace)

**Physical separation + DHT isolation = true isolation**

---

## Vouch vs Token vs Signature

These three concepts work together:

| Concept | Purpose | Scope | Lifetime |
|---------|---------|-------|----------|
| **Vouch** | Proves identity to federation | Federation-specific | Long (1 year) |
| **Biscuit Token** | Grants skill access | Ad-hoc | Short or unlimited |
| **Signature** | Proves cryptographic ownership | Message-specific | Single message |

### Example Flow

```
1. Alice logs in → Gets vouch for "finance" federation
   ├── Vouch stored in ~/.config/sam/federations/finance.db
   └── Valid for 1 year

2. Alice publishes agent → Signs Agent Card with Ed25519 key
   ├── Signature proves Alice owns the card
   └── Signature is part of the card

3. Alice grants partner access → Creates Biscuit token
   ├── "partner-bot;allow_skill=risk-audit"
   ├── Shared via secure channel
   └── No expiry (revoke by removing from app)

4. Partner calls Alice's agent
   ├── Partner sends vouch (proves they're in the federation)
   ├── Partner sends Biscuit token (proves they can access risk-audit)
   ├── Alice verifies both → Executes
   └── Alice returns signed response
```

---

## Managing Multiple Federations

An agent can participate in multiple federations:

```bash
# Alice is in finance federation
sam-agent identity login --hub https://identity.acme.corp

# Alice is also invited to operations (different hub)
sam-agent identity login --hub https://ops-identity.acme.corp

# Alice publishes to both
sam-agent publish --skill risk-audit --mcp-port 8080
sam-agent publish --skill audit-log --mcp-port 8090

# Each federation has its own storage
~/.config/sam/federations/finance.db
~/.config/sam/federations/operations.db
```

Each federation database:
- Stores its own set of identity vouches
- Publishes to its own DHT namespace
- Has separate reputation scores

---

## Disaster Recovery

### Backing Up a Federation

```bash
# Backup federation DB
cp ~/.config/sam/federations/finance.db ~/backups/finance.db.backup

# Backup identity credentials
cp ~/.config/sam/identity/ ~/backups/identity.backup
```

### Restoring a Federation

```bash
# Restore from backup
cp ~/backups/finance.db.backup ~/.config/sam/federations/finance.db

# Agent will continue with cached vouch
sam-agent call risk-audit
```

If the vouch is stale, re-authenticate:
```bash
sam-agent identity login --hub https://identity.acme.corp
```

---

## Performance: Why bbolt?

**bbolt is chosen because:**

1. **ACID transactions**: Consistent reads/writes
2. **Single file**: No distributed consensus needed
3. **Fast**: B+ tree structure, in-process
4. **No external dependencies**: Pure Go, no server

**Alternative approaches we rejected:**

- **SQLite**: Requires SQL schema, more complex
- **Redis**: Requires central server (defeats isolation)
- **DynamoDB/PostgreSQL**: Vendor lock-in, centralized
- **In-memory map**: No persistence across restarts

bbolt gives us **federated isolation + local performance**.

---

## Storage Layout Example (Acme Corp)

```
Acme Corp IT
└── ~/.config/sam/
    ├── identity/
    │   ├── keystore.json       (Alice's Ed25519 key)
    │   └── vouch.json          (Alice's vouch for "finance")
    │
    └── federations/
        ├── finance.db          (Finance federation)
        │   ├── identities: {alice → 12D3Koo...}
        │   ├── vouches: {12D3Koo... → {subject: alice, ...}}
        │   ├── reputation: {alice → {score: 98}}
        │   └── cache: {risk-audit → [12D3Koo...]}
        │
        ├── operations.db       (Ops federation)
        │   ├── identities: {bob → 12D3Koo...}
        │   ├── vouches: {12D3Koo... → {subject: bob, ...}}
        │   ├── reputation: {bob → {score: 87}}
        │   └── cache: {incident-response → [12D3Koo...]}
        │
        └── public.db           (Default federation)
            ├── identities: {...}
            ├── vouches: {...}
            └── cache: {...}

Federated Database Architecture:
- Finance.db is owned by Finance org
- Operations.db is owned by Ops org
- No shared database
- No central trust
```

---

## Next Steps

- **[Identity & Vouch System](#/concepts/identity.md)**: Deep dive into how identity works
- **[Biscuit Authorization](#/concepts/biscuit.md)**: How skill-based access control works
- **[A2A Protocol](#/concepts/a2a-protocol.md)**: How agents authenticate and call each other
