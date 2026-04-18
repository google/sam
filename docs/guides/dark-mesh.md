# Enterprise Dark Mesh Guide

## Scenario: Acme Corp's Sovereign Agent Network

Acme Corp has three business units:
- **Finance**: Risk auditors and compliance checkers
- **Operations**: Workflow agents and incident responders
- **Vendor Network**: Partner agents from external organizations

They need:
- **Network isolation**: Finance agents cannot discover Operations agents
- **Identity verification**: Only trusted partners can join
- **Fine-grained access**: Partner agents can only access specific skills
- **Audit transparency**: Every call and credential is inspectable

This guide walks through setting up SAM for this scenario.

---

## Step 1: Initialize Your First Federation

Start by creating a federation called `finance`:

```bash
# Create the federation
sam mesh federations create finance

# Verify it exists
sam mesh federations list
```

Output:
```json
{
  "federations": [
    {
      "name": "finance",
      "id": "fed-abc123...",
      "agents": 0,
      "created_at": "2026-04-18T10:00:00Z"
    }
  ]
}
```

**What happened:**
- SAM created a bbolt database at `~/.config/sam/federations/finance.db`
- The database has buckets: `identities`, `vouches`, `reputation`, `cache`
- The federation ID (`fed-abc123`) is derived from the name (deterministic)
- DHT discovery for this federation will use `/sam/fed/fed-abc123` namespace

---

## Step 2: Authenticate as a Federation Member

Each agent needs a vouch from the federation before it can publish or call.

### For Internal Agents (Finance Team)

Finance agents authenticate directly:

```bash
# Login with a federation hub (your identity server)
sam identity login --hub https://identity.acme.corp --federation finance

# Enter credentials
Username: alice.smith@acme.corp
Password: ****
```

Output:
```
✓ Identity verified
✓ Vouch stored at ~/.config/sam/identity/vouch.json
✓ Federation: finance
✓ Subject: alice.smith
```

**What happened:**
- SAM contacted the hub at `https://identity.acme.corp`
- The hub verified Alice's credentials and issued a **Vouch** (cryptographic proof)
- The vouch was stored locally in bbolt (not fetched on every call)
- The vouch is bound to the federation (`finance`) and Alice's identity

**Note on the Hub:**
The hub is a simple HTTP service. It:
1. Verifies credentials (LDAP, OAuth, however you want)
2. Issues a Vouch (signed JSON with Alice's Ed25519 PeerID)
3. Returns the vouch

The hub is **not a gateway**. Once the vouch is cached locally, the hub is no longer needed.

### For Partner Agents (Vendor Network)

Partner organizations also authenticate, but through their own identity server:

```bash
# Partner setup: Vendor Inc authenticates with their own hub
sam identity login --hub https://auth.vendor-inc.com --federation finance
```

**What happened:**
- Vendor Inc's agent contacted *their own* identity server
- Got a vouch from that server
- The vouch is still valid in SAM because SAM trusts the *issuer signature*, not a central authority

**Key insight:** Each organization can use their own identity infrastructure. SAM only cares that the vouch is cryptographically signed.

---

## Step 3: Publish an Agent with Skills

Now Alice publishes a risk-audit agent:

```bash
sam publish \
  --federation finance \
  --skill risk-audit \
  --skill compliance-check \
  --mcp-port 8080
```

Output:
```json
{
  "peer_id": "12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK",
  "alg": "libp2p-ed25519",
  "signature": "...",
  "agent_card": {
    "name": "Risk Audit Agent",
    "skills": [
      {
        "name": "risk-audit",
        "description": "Audit risk controls"
      },
      {
        "name": "compliance-check",
        "description": "Check compliance with regulations"
      }
    ],
    "resources": [
      {
        "name": "risk-audit",
        "kind": "tool",
        "endpoint": "http://127.0.0.1:8080"
      }
    ]
  },
  "issued_at": "2026-04-18T10:15:00Z"
}
```

**What happened:**
1. SAM generated a libp2p node (or reused an existing keypair)
2. Created an Agent Card signed with the node's Ed25519 key
3. Published the card to `/sam/fed/finance` DHT namespace
4. Started a local MCP bridge listening on `localhost:8080`

**Note:** The DHT announcement uses the federation namespace, so only agents in the `finance` federation will discover this agent.

---

## Step 4: Partner Access with Biscuit Tokens

Now Acme wants to give Vendor Inc access to only the `risk-audit` skill, not `compliance-check`.

Alice creates a Biscuit token for the vendor:

```bash
# Create a token that only allows risk-audit skill
sam economy biscuit create \
  --subject "vendor-bot@vendor-inc.com" \
  --allow-skill risk-audit
```

Output:
```
vendor-bot@vendor-inc.com;allow_skill=risk-audit
```

This token is shared with Vendor Inc (via secure channel, e.g., email, encrypted channel).

---

## Step 5: Partner Calls a Skill

Vendor Inc's agent (partner-bot) uses the token to call Alice's risk-audit:

```bash
sam call risk-audit \
  --federation finance \
  --biscuit "vendor-bot@vendor-inc.com;allow_skill=risk-audit" \
  --message "Check my vendor data against risk controls"
```

**What happens behind the scenes:**

### Discovery
```
partner-bot queries /sam/fed/finance DHT
  ↓
Finds peer alice.smith (publishing risk-audit)
  ↓
Connects to alice.smith on /sam/a2a/1.0 stream
```

### Authentication (Federation Gate)
```
partner-bot sends vouch to alice.smith
  ↓
alice.smith checks if partner-bot's PeerID is in the finance vouch database
  ↓
✓ Vouch found → Continue
```

### Authorization (Biscuit Gate)
```
partner-bot sends Biscuit token: "vendor-bot@vendor-inc.com;allow_skill=risk-audit"
  ↓
alice.smith parses the token → allowed_skills = [risk-audit]
  ↓
alice.smith checks: is "risk-audit" in allowed_skills?
  ↓
✓ Yes → Execute the skill
```

### Execution
```
alice.smith calls local MCP server on localhost:8080
  ↓
MCP server processes the request
  ↓
Response sent back to partner-bot
```

---

## Step 6: Audit with sam inspect

Before sharing the Biscuit token, Alice can verify exactly what access it grants:

```bash
sam inspect biscuit "vendor-bot@vendor-inc.com;allow_skill=risk-audit"
```

Output:
```
Biscuit Token Analysis
======================

Subject: vendor-bot@vendor-inc.com
Allowed Skills: risk-audit

Human-Readable Summary:
This token issued to 'vendor-bot@vendor-inc.com' allows execution of 'risk-audit' skill only.
```

If the token has multiple skills:

```bash
sam inspect biscuit "vendor-bot@vendor-inc.com;allow_skill=risk-audit,compliance-check"
```

Output:
```
Biscuit Token Analysis
======================

Subject: vendor-bot@vendor-inc.com
Allowed Skills: 
  - risk-audit
  - compliance-check

Human-Readable Summary:
This token issued to 'vendor-bot@vendor-inc.com' allows execution of 2 skills:
risk-audit, compliance-check.
```

---

## Step 7: Dry-Run for Safety

Before publishing an agent to the live federation, Alice can preview the Agent Card:

```bash
sam publish \
  --federation finance \
  --skill risk-audit \
  --mcp-port 8080 \
  --dry-run=client
```

Output:
```json
{
  "peer_id": "12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK",
  "alg": "libp2p-ed25519",
  "agent_card": {
    "name": "Risk Audit Agent",
    "skills": ["risk-audit"],
    "resources": [...]
  },
  "issued_at": "2026-04-18T10:15:00Z"
}
```

**Key difference:** No network activity. The card is built locally, signed, and displayed. Perfect for auditing before commit.

---

## Step 8: Dry-Run a Call Request

Partner-bot can validate the request structure before sending it:

```bash
sam call risk-audit \
  --federation finance \
  --biscuit "vendor-bot@vendor-inc.com;allow_skill=risk-audit" \
  --message "Check vendor data" \
  --dry-run=client
```

Output:
```json
{
  "target": "risk-audit",
  "capability": "risk-audit",
  "biscuit": "vendor-bot@vendor-inc.com;allow_skill=risk-audit",
  "payment": {
    "amount": 1,
    "asset": "sam-credit",
    "nonce": "1713451200000000000",
    "capability": "risk-audit"
  },
  "message": "Check vendor data"
}
```

---

## Step 9: Inspect an Agent Card

Vendor Inc wants to verify that Alice's agent really publishes `risk-audit` skill:

First, they get the agent card (via DHT discovery or shared channel):

```bash
sam inspect card '{
  "peer_id": "12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK",
  "alg": "libp2p-ed25519",
  "signature": "...",
  "agent_card": {
    "name": "Risk Audit Agent",
    "skills": ["risk-audit", "compliance-check"],
    "resources": [...]
  },
  "issued_at": "2026-04-18T10:15:00Z"
}'
```

Output:
```
Agent Card Analysis
===================

Peer ID: 12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK
Algorithm: libp2p-ed25519
Signature: Verified ✓

Skills Available:
  - risk-audit
  - compliance-check

Resources:
  - Name: risk-audit
    Kind: tool
    Endpoint: http://127.0.0.1:8080

Issued: 2026-04-18T10:15:00Z
```

---

## Full Scenario Summary

### Architecture

```
Finance Federation (isolated namespace: /sam/fed/finance)
│
├── alice.smith (Risk Audit Agent)
│   ├─ Skill: risk-audit
│   ├─ Skill: compliance-check
│   └─ Vouch: From finance.acme.corp hub
│
├── bob.jones (Compliance Agent)
│   ├─ Skill: compliance-check
│   └─ Vouch: From finance.acme.corp hub
│
└── partner-bot (Vendor Inc)
    ├─ Skill: (none, external)
    └─ Vouch: From vendor-inc.com hub
    └─ Token: "partner-bot;allow_skill=risk-audit"
       (can ONLY call risk-audit, not compliance-check)

Operations Federation (isolated namespace: /sam/fed/operations)
│
├── workflow-bot
│   └─ Skill: incident-response
```

### Trust Flow

```
1. Identity verification (Vouch)
   - alice.smith proves identity via finance.acme.corp
   - partner-bot proves identity via vendor-inc.com
   - SAM trusts the issuer signature, not a central authority

2. Network isolation (DHT namespace)
   - Finance agents only discover in /sam/fed/finance
   - Operations agents only discover in /sam/fed/operations
   - No cross-federation discovery

3. Skill gating (Biscuit)
   - partner-bot gets token: "...;allow_skill=risk-audit"
   - alice.smith verifies skill is in the allowed list
   - Calls to compliance-check are rejected

4. Audit trail (sam inspect)
   - Before sharing tokens: sam inspect biscuit <token>
   - Before publishing: sam publish --dry-run=client
   - Before calling: sam call <target> --dry-run=client
```

### No Central Authority

- **No identity gateway**: Each org uses their own hub (or none)
- **No API gateway**: Agents call each other directly
- **No token server**: Biscuits are local caveats, not fetched
- **No audit server**: Everything is inspectable locally

---

## Next Steps

1. **Setup Your Federations**: [Federation Setup Guide](/guides/federation-setup.md)
2. **Publish Your First Agent**: [Publishing Guide](/guides/publish-agent.md)
3. **CLI Reference**: Full command documentation at [CLI Reference](/cli/reference.md)
4. **Technical Deep Dive**: Understand federation storage at [Federation & Storage](/concepts/federation.md)
