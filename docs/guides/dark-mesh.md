# Dark Mesh: End-to-End Walkthrough

This guide shows a full SAM flow using passport-based authentication and Biscuit capability authorization.

## Scenario

- Team A publishes a private capability (`risk-audit`).
- Team B discovers and calls it.
- All traffic remains peer-to-peer.

## Step 1: Start a Node

```bash
sam-agent up --dht-mode server
```

Keep this running in one terminal.

## Step 2: Authenticate Identity

In another terminal:

```bash
sam-agent identity login --hub https://identity.example.com
sam-agent identity whoami
```

This stores local credentials and a passport biscuit.

## Step 3: Publish a Capability

Assuming your MCP server is on `:8080`:

```bash
sam-agent publish --skill risk-audit --mcp-port 8080
```

Optional safety preview:

```bash
sam-agent publish --skill risk-audit --mcp-port 8080 --dry-run=client
```

## Step 4: Discover Agents

```bash
sam-agent mesh get agents
sam-agent mesh get agents --capability risk-audit -o json
```

## Step 5: Call the Capability

```bash
sam-agent call risk-audit --message "audit this report"
```

Optional request validation:

```bash
sam-agent call risk-audit --message "audit this report" --dry-run=client
```

## Step 6: Audit Artifacts

```bash
sam-agent inspect biscuit "partner-bot;allow_skill=risk-audit"
sam-agent inspect card '{"peer_id":"...","agent_card":{...}}'
```

## Troubleshooting

1. No peers found:

```bash
sam-agent mesh get agents --watch
```

2. Unauthorized errors:

```bash
sam-agent identity whoami
sam-agent identity login --hub https://identity.example.com
```

3. Connectivity issues:

```bash
sam-agent up --relay-service --run-for 30s
```

4. Detailed logs:

```bash
SAM_DEBUG=1 sam-agent call risk-audit --message "test"
```

## Security Notes

- Identity authentication is passport-based at peer establishment time.
- Authorization remains capability-scoped via Biscuit caveats.
- Runtime uses a fixed default mesh namespace.
