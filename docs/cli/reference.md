# SAM CLI Reference

SAM uses a kubectl-style command hierarchy with shared node/runtime flags.

## Global Flags

Most commands accept these shared flags:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--listen` | stringSlice | `/ip4/0.0.0.0/udp/0/quic-v1` | libp2p listen multiaddrs |
| `--bootstrap` | stringSlice | empty | bootstrap peer multiaddrs |
| `--dht-mode` | string | `client` | DHT mode: `client`, `server`, `auto` |
| `--relay-service` | bool | `false` | enable relay service |
| `--user-agent` | string | `sam/0.1.0` | libp2p user-agent |
| `--run-for` | duration | `0` | optional duration before graceful shutdown |
| `--hub` | string | empty | OIDC hub URL for identity login/passport issuance |
| `--identity` | string | empty | PEM-encoded Ed25519 private key path |
| `--debug` | bool | `false` | enable debug logging |

## sam-agent identity

Authentication and credential management.

### sam-agent identity login

Authenticate with the hub using device flow and store credentials plus passport biscuit locally.

```bash
sam-agent identity login --hub https://identity.acme.corp
```

### sam-agent identity whoami

Show current authenticated identity.

```bash
sam-agent identity whoami
```

## sam-agent publish

Publish an agent card to DHT namespaces.

### Quick Mode

```bash
sam-agent publish --skill risk-audit --mcp-port 8080
```

Useful flags:
- `--skill` or repeatable `--capability`
- `--mcp-port`
- `--republish-every`
- `--dry-run=client|server`
- `--resource-name`, `--resource-kind`, `--resource-endpoint`, `--resource-description`

### sam-agent publish card

```bash
sam-agent publish card --file agent-card.json --republish-every 5m
```

### sam-agent publish mcp

```bash
sam-agent publish mcp --port 8080 --name "Risk Audit Tool"
```

## sam-agent call

Execute an A2A task against a remote agent.

```bash
sam-agent call risk-audit --message "Audit the Q1 risk report"
```

Useful flags:
- `--message`
- `--biscuit`
- `--timeout`
- `--amount`, `--asset`, `--nonce`
- `--dry-run=client|server`

## sam-agent proxy

Start a local HTTP proxy that tunnels over SAM.

```bash
sam-agent proxy --port 8081
```

Useful flags:
- `--port`
- `--target-header`
- `--biscuit`
- `--timeout`

## sam-agent inspect

Decode local artifacts for auditing.

### sam-agent inspect biscuit

```bash
sam-agent inspect biscuit "alice;allow_skill=risk-audit,weather-bot"
```

### sam-agent inspect card

```bash
sam-agent inspect card '{"peer_id":"...","agent_card":{...}}'
```

## sam-agent mesh

Mesh visibility commands.

### sam-agent mesh get agents

```bash
sam-agent mesh get agents
sam-agent mesh get agents --capability risk-audit
sam-agent mesh get agents --watch -o json
```

## sam-agent up

Start a SAM node and wait for shutdown.

```bash
sam-agent up \
  --listen /ip4/0.0.0.0/udp/4001/quic-v1 \
  --bootstrap /ip4/192.168.1.100/udp/4001/quic-v1/p2p/12D3KooXA7cBj4VKrpv7HzKLmvnWKLVqZZHJm9NyN6Td3Y4hMWjK
```

## Patterns

### Publish workflow

```bash
# Preview card locally
sam-agent publish --skill new-capability --mcp-port 9000 --dry-run=client

# Publish to mesh
sam-agent publish --skill new-capability --mcp-port 9000
```

### Call workflow with Biscuit

```bash
TOKEN="partner-bot;allow_skill=risk-audit"
sam-agent inspect biscuit "$TOKEN"
sam-agent call risk-audit --biscuit "$TOKEN" --message "Check compliance"
```

## Dry-Run Philosophy

Dry-run modes support audit transparency and safe rollout:

- `--dry-run=client`: build and validate payloads locally, no network activity
- `--dry-run=server`: initialize runtime, skip final network commit

Use these to preview behavior, capture JSON artifacts for security review, and gate CI checks.

## Next Steps

- **[User Journey Guide](#/guides/dark-mesh.md)**: scenario walkthrough
- **[FAQ](#/faq.md)**: troubleshooting and operational tips
