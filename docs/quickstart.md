# Quick Start Reference

## Installation

```bash
git clone https://github.com/your-org/sam.git
cd sam
make build
./bin/sam --help
```

## First Steps (5 Minutes)

### 1. Create a Federation

```bash
sam mesh federations create myfed
```

### 2. Authenticate

```bash
sam identity login --hub https://identity.example.com --federation myfed
```

### 3. Publish an Agent

```bash
# Start a local MCP server on port 8080
# Then publish it:
sam publish \
  --federation myfed \
  --skill my-skill \
  --mcp-port 8080
```

### 4. Call an Agent

```bash
sam call my-skill \
  --federation myfed \
  --message "Do something"
```

---

## Common Commands

### Federation Management

```bash
# List federations
sam mesh federations list

# Get agents in federation
sam mesh get agents --federation myfed

# Delete federation
sam mesh federations drop myfed --confirm
```

### Identity

```bash
# Show current identity
sam identity whoami --federation myfed

# Re-authenticate (if vouch expired)
sam identity login --hub https://identity.example.com --federation myfed
```

### Publishing & Calling

```bash
# Publish with dry-run (no network)
sam publish --skill test --mcp-port 8080 --dry-run=client

# Call with dry-run (no network)
sam call test --message "hello" --dry-run=client

# Call with custom Biscuit token
sam call test \
  --message "hello" \
  --biscuit "user;allow_skill=test"

# Call with timeout
sam call test --message "hello" --timeout 30s
```

### Auditing

```bash
# Inspect a Biscuit token
sam inspect biscuit "alice;allow_skill=weather-bot"

# Inspect an Agent Card
sam inspect card '{"peer_id":"...","agent_card":{...}}'
```

---

## Global Flags

```bash
--federation <name>   Scope to specific federation
--debug               Enable debug logging
--timeout <duration>  Operation timeout
--output json         JSON output format
```

---

## File Locations

```
~/.config/sam/
├── identity/
│   ├── keystore.json      (private key)
│   ├── vouch.json         (federation vouch)
│   └── credentials.keyring (encrypted passwords)
└── federations/
    ├── myfed.db           (federation database)
    └── ...
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "vouch expired" | `sam identity login --federation <name> ...` |
| "skill not allowed" | Check Biscuit token: `sam inspect biscuit <token>` |
| "no peers found" | Publish agent first: `sam publish --skill <name> --mcp-port <port>` |
| "connection timeout" | Check network: `sam up --federation <name> --run-for 30s` |

---

## Key Concepts

**Federation**: Isolated P2P network where agents discover and call each other

**Vouch**: Identity credential, issued by hub, cached locally

**Biscuit**: Skill-access credential, plain-text format `subject;allow_skill=X,Y,Z`

**Agent Card**: Signed manifest of skills published to DHT

**A2A**: Agent-to-Agent RPC protocol over libp2p

---

## Documentation

- **[Overview](/README.md)**: What SAM is and why it matters
- **[User Journey](/guides/dark-mesh.md)**: Step-by-step walkthrough
- **[CLI Reference](/cli/reference.md)**: Full command documentation
- **[Concepts](/concepts/federation.md)**: Technical deep dives
- **[Testing](/testing.md)**: How to run and write tests
- **[FAQ](/faq.md)**: Common questions
- **[Glossary](/glossary.md)**: Terminology reference

---

## Help

```bash
# Any command help
sam <command> --help

# Verbose logging
SAM_DEBUG=1 sam <command>

# Report bugs
https://github.com/your-org/sam/issues
```

---

Happy meshing! 🚀
