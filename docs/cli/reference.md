# SAM CLI Reference

SAM uses a **kubectl-style command hierarchy** with shared flags, subcommands, and consistent output formats.

---

## Global Flags

All commands accept these flags:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--federation` | string | "" | Federation name (scopes operations to isolated namespace) |
| `--debug` | bool | false | Enable debug logging (verbose output) |
| `--timeout` | duration | 30s | Operation timeout |
| `--output` / `-o` | string | "json" | Output format: "json" or "text" |

---

## sam identity

Authentication and credential management.

### sam identity login

Authenticate with a federation hub and store vouch locally.

```bash
sam identity login \
  --hub https://identity.acme.corp \
  --federation finance
```

**Flags:**
- `--hub` (required): URL of identity server
- `--federation` (optional): Federation name (defaults to "default")

**Output:**
```
✓ Identity verified
✓ Vouch stored
✓ Federation: finance
✓ Subject: alice.smith@acme.corp
```

**What it does:**
1. Prompts for username/password
2. Contacts the hub to verify credentials
3. Receives a signed Vouch (JSON)
4. Stores vouch in `~/.config/sam/identity/vouch.json`
5. Stores credentials in secure OS keyring (optional)

**Behind the scenes:**
- The vouch is a signed credential proving your identity to the federation
- The hub is not contacted again (vouch is cached locally)
- If the vouch expires, run login again

---

### sam identity whoami

Show current authenticated identity.

```bash
sam identity whoami --federation finance
```

**Output:**
```
Subject: alice.smith@acme.corp
Vouch: Valid until 2027-04-18
Federation: finance
PeerID: 12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK
```

---

## sam publish

Publish an agent to a federation DHT.

### Quick Mode

For simple single-skill agents:

```bash
sam publish \
  --federation finance \
  --skill risk-audit \
  --mcp-port 8080
```

**Flags:**
- `--skill`: Single skill name (convenience alias for --capability)
- `--capability`: Repeatable flag for multiple skills
- `--mcp-port` (required): Local MCP server port
- `--republish-every`: Refresh interval (default 2m)
- `--dry-run`: "client" (build locally) or "server" (skip DHT publish)
- `--resource-name`: MCP resource name
- `--resource-kind`: MCP resource kind (default "tool")
- `--resource-endpoint`: Override resource endpoint
- `--resource-description`: Human-readable description

**Dry-Run Modes:**

Preview the Agent Card without network:
```bash
sam publish \
  --federation finance \
  --skill risk-audit \
  --mcp-port 8080 \
  --dry-run=client
```

Output: Agent Card JSON (no network activity)

Skip DHT publish but build network:
```bash
sam publish \
  --federation finance \
  --skill risk-audit \
  --mcp-port 8080 \
  --dry-run=server
```

Output: Agent Card JSON (node started but DHT publish skipped)

---

### sam publish card

Explicit card publishing (advanced).

```bash
sam publish card \
  --federation finance \
  --file agent-card.json \
  --republish-every 5m
```

**Flags:**
- `--file`: Path to pre-built Agent Card JSON
- `--republish-every`: Refresh interval

---

### sam publish mcp

Publish an MCP server.

```bash
sam publish mcp \
  --federation finance \
  --port 8080 \
  --name "Risk Audit Tool"
```

**Flags:**
- `--port`: MCP server port
- `--name`: Resource name

---

## sam call

Execute an A2A task against a remote agent.

### Basic Call

```bash
sam call risk-audit \
  --federation finance \
  --message "Audit the Q1 risk report"
```

**Flags:**
- `--message` (required): Natural-language prompt
- `--biscuit`: Credential token (default "dev-biscuit")
- `--timeout`: Call timeout (default 20s)
- `--amount`: Micropayment amount (default 1)
- `--asset`: Micropayment asset (default "sam-credit")
- `--nonce`: Micropayment nonce (auto-generated if empty)
- `--dry-run`: "client" (validate locally) or "server" (skip A2A execute)

**Dry-Run Modes:**

Validate request without network:
```bash
sam call risk-audit \
  --federation finance \
  --message "Audit Q1" \
  --dry-run=client
```

Output: Request JSON (no network activity)

**Output:**
```json
{
  "jsonrpc": "2.0",
  "id": "sam-call",
  "method": "message",
  "params": {
    "message": "Audit the Q1 risk report"
  }
}
```

---

## sam inspect

Decode and explain cryptographic artifacts for auditing.

### sam inspect biscuit

Parse and explain a Biscuit token.

```bash
sam inspect biscuit "alice;allow_skill=risk-audit,weather-bot"
```

**Output (Text):**
```
Biscuit Token Analysis
======================

Subject: alice
Allowed Skills: 
  - risk-audit
  - weather-bot

Human-Readable Summary:
This token issued to 'alice' allows execution of 2 skills:
risk-audit, weather-bot.
```

**Output (JSON):**
```bash
sam inspect biscuit "alice;allow_skill=risk-audit" --output json
```

```json
{
  "subject": "alice",
  "allowed_skills": ["risk-audit"]
}
```

**Use case:** Before sharing a Biscuit token, verify it grants only intended skills.

---

### sam inspect card

Decode an Agent Card JSON.

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

**Output:**
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

**Use case:** Verify an agent's published skills before calling it.

---

## sam mesh

Federation and network management.

### sam mesh federations

Manage isolated federation namespaces.

#### sam mesh federations create

Create a new federation.

```bash
sam mesh federations create finance
```

**Output:**
```json
{
  "name": "finance",
  "id": "fed-abc123...",
  "created_at": "2026-04-18T10:00:00Z"
}
```

**What it does:**
1. Generates a deterministic federation ID from the name
2. Creates a bbolt database at `~/.config/sam/federations/<name>.db`
3. Initializes buckets: identities, vouches, reputation, cache

---

#### sam mesh federations list

List all federations.

```bash
sam mesh federations list
```

**Output:**
```json
{
  "federations": [
    {
      "name": "finance",
      "id": "fed-abc123...",
      "agents": 3,
      "created_at": "2026-04-18T10:00:00Z"
    },
    {
      "name": "operations",
      "id": "fed-def456...",
      "agents": 2,
      "created_at": "2026-04-18T10:05:00Z"
    }
  ]
}
```

---

#### sam mesh federations drop

Delete a federation.

```bash
sam mesh federations drop finance --confirm
```

**Flags:**
- `--confirm`: Require explicit confirmation to prevent accidental deletion

**Output:**
```
✓ Federation 'finance' dropped
✓ Database deleted: ~/.config/sam/federations/finance.db
```

---

### sam mesh get agents

List agents in a federation.

```bash
sam mesh get agents --federation finance
```

**Output:**
```json
{
  "agents": [
    {
      "peer_id": "12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK",
      "name": "Risk Audit Agent",
      "skills": ["risk-audit", "compliance-check"],
      "published_at": "2026-04-18T10:15:00Z"
    }
  ]
}
```

---

## sam up

Start a SAM node and wait for shutdown.

```bash
sam up \
  --federation finance \
  --listen /ip4/0.0.0.0/tcp/4001 \
  --bootstrap /ip4/192.168.1.100/tcp/4001/p2p/12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK
```

**Flags:**
- `--listen`: Multiaddr to listen on (repeatable)
- `--bootstrap`: Bootstrap peer address (repeatable)
- `--run-for`: Duration to run (e.g., "10m", default infinite)
- `--federation`: Federation to join

**Use case:** Run a persistent SAM node for long-lived agents or relays.

---

## Patterns and Best Practices

### Workflow: Publish a New Agent

```bash
# 1. Preview the card locally
sam publish \
  --federation finance \
  --skill new-capability \
  --mcp-port 9000 \
  --dry-run=client

# 2. If satisfied, publish to DHT
sam publish \
  --federation finance \
  --skill new-capability \
  --mcp-port 9000
```

### Workflow: Call with Biscuit Authorization

```bash
# 1. Create a Biscuit token for a partner
TOKEN="partner-bot;allow_skill=risk-audit"

# 2. Inspect the token before sharing
sam inspect biscuit "$TOKEN"

# 3. Partner uses token to call
sam call risk-audit \
  --federation finance \
  --biscuit "$TOKEN" \
  --message "Check compliance"
```

### Workflow: Audit a Call Request

```bash
# 1. Validate the call structure without network
sam call weather-bot \
  --federation finance \
  --message "Get forecast" \
  --dry-run=client

# 2. Review the JSON
# 3. If satisfied, remove --dry-run
sam call weather-bot \
  --federation finance \
  --message "Get forecast"
```

---

## Output Formats

All commands support `--output` flag (default "json", values "json" or "text").

**JSON output:**
```bash
sam mesh federations list --output json
```

**Text output:**
```bash
sam mesh federations list --output text
```

---

## Federation Scoping

Many commands require `--federation` to specify which federation to operate in.

If not provided, defaults to "default" federation.

```bash
# Explicit federation
sam publish --federation finance --skill risk-audit --mcp-port 8080

# Uses "default" federation
sam publish --skill risk-audit --mcp-port 8080
```

---

## Dry-Run Philosophy

**Dry-run modes exist to support audit transparency:**

- `--dry-run=client`: Build and sign locally, show output, no network
- `--dry-run=server`: Start network, build artifacts, skip final commit (DHT publish, A2A execute)

Use these to:
1. Preview what will be published/called
2. Extract JSON for security scanning
3. Verify signatures before committing
4. Integrate with CI/CD approval workflows

---

## Next Steps

- **[User Journey Guide](#/guides/dark-mesh.md)**: Full scenario walkthrough
- **[Concepts](#/concepts/federation.md)**: Technical deep dive
