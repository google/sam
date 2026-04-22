# Quick Start Reference

## Installation

```bash
git clone https://github.com/aojea/sam.git
cd sam
make build
./bin/sam-agent --help
```

## First Steps (5 Minutes)

### 1. Authenticate

```bash
sam-agent identity login --hub https://identity.example.com
```

### 2. Publish an Agent

```bash
# Start a local MCP server on port 8080
sam-agent publish --skill my-skill --mcp-port 8080
```

### 3. Call an Agent

```bash
sam-agent call my-skill --message "Do something"
```

---

## Common Commands

### Mesh

```bash
# Get visible agents
sam-agent mesh get agents

# Watch new agents in real time
sam-agent mesh get agents --watch
```

### Identity

```bash
# Show current identity
sam-agent identity whoami

# Re-authenticate
sam-agent identity login --hub https://identity.example.com
```

### Publishing and Calling

```bash
# Publish with dry-run (no network)
sam-agent publish --skill test --mcp-port 8080 --dry-run=client

# Call with dry-run (no network)
sam-agent call test --message "hello" --dry-run=client

# Call with custom Biscuit token
sam-agent call test --message "hello" --biscuit "user;allow_skill=test"
```

### Auditing

```bash
# Inspect a Biscuit token
sam-agent inspect biscuit "alice;allow_skill=weather-bot"

# Inspect an Agent Card
sam-agent inspect card '{"peer_id":"...","agent_card":{...}}'
```

---

## Global Flags

```bash
--debug   Enable debug logging
```

---

## File Locations

```
~/.config/sam/
├── identity/
│   └── credentials.json      (hub/device credentials and passport biscuit)
└── federations/
    └── default.db            (default mesh state database)
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "passport expired" | `sam-agent identity login --hub <url>` |
| "skill not allowed" | Check Biscuit token: `sam-agent inspect biscuit <token>` |
| "no peers found" | Publish agent first: `sam-agent publish --skill <name> --mcp-port <port>` |
| "connection timeout" | Check network: `sam-agent up --run-for 30s` |

---

## Key Concepts

**Passport Biscuit**: Hub-issued identity credential bound to peer ID and default federation audience.

**Biscuit**: Skill-access credential, plain-text format `subject;allow_skill=X,Y,Z`.

**Agent Card**: Signed manifest of skills published to DHT.

**A2A**: Agent-to-agent RPC protocol over libp2p.

---

## Documentation

- **[Overview](#/README.md)**: What SAM is and why it matters
- **[User Journey](#/guides/dark-mesh.md)**: Step-by-step walkthrough
- **[CLI Reference](#/cli/reference.md)**: Full command documentation
- **[Testing](#/testing.md)**: How to run and write tests
- **[FAQ](#/faq.md)**: Common questions
- **[Glossary](#/glossary.md)**: Terminology reference

---

## Help

```bash
# Any command help
sam-agent <command> --help

# Verbose logging
SAM_DEBUG=1 sam-agent <command>

# Report bugs
https://github.com/aojea/sam/issues
```
