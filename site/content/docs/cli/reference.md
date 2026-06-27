# CLI Reference

The current repository exposes two CLIs:

- `sam-node`
- `sam-hub`

## sam-node

```bash
sam-node --help
```

### sam-node join

Join the Sovereign Agent Mesh hub and enroll the node.

```bash
sam-node join [hub_url] [flags]
```

If `hub_url` is omitted, you will be prompted to join the default community testing network (`https://bananas.sam-mesh.dev`). This command initiates an interactive OIDC device login flow and stores the returned identity Biscuit token and generated keypair in the database.

Flags:

*   `--data-dir`: Override directory for the agent store (defaults to OS user config dir).

### sam-node run

Start the sovereign mesh node.

```bash
sam-node run [flags]
```

Flags:

*   `--data-dir`: Override directory for the agent store (defaults to OS user config dir) where identity and private keys are loaded.
*   `--bind-addr`: Local TCP address for the HTTP server (MCP and Sidecar API) (default `"127.0.0.1:8080"`).
*   `--listen`: libp2p Listen Addrs (default `[/ip4/0.0.0.0/udp/5001/quic-v1,/ip4/0.0.0.0/tcp/5002]`).
*   `--jwt`: Pre-fetched JWT token to enroll dynamically.
*   `--jwt-path`: Path to a file containing a pre-fetched JWT token.
*   `--oidc-issuer`: OIDC Issuer URL for M2M auto-enrollment.
*   `--client-id`: OIDC Client ID for M2M auto-enrollment.
*   `--client-secret`: OIDC Client Secret for M2M auto-enrollment.
*   `--api-token`: Static Bearer token for API authorization.
*   `--log-level`: Log level (debug, info, warn, error) (default `"info"`).

Examples:

```bash
# Start using saved identity
sam-node run

# Start with explicit OIDC details
sam-node run --oidc-issuer https://issuer.example.com --client-id my-id --client-secret my-secret

# Start and bind HTTP API to all interfaces (e.g. inside Docker)
sam-node run --bind-addr 0.0.0.0:8080
```

## sam-hub

```bash
sam-hub --help
```

`sam-hub` runs the OIDC bridge, issues identity biscuits, and gates unauthenticated peers.

Flags:

- `--issuer`: OIDC issuer URL
- `--client-id`: OIDC client ID
- `--client-secret`: OIDC client secret
- `--key`: 32-byte hex seed used to derive Ed25519 biscuit signing key
- `--listen`: repeatable libp2p listen addresses
- `--mesh`: mesh name
- `--public-url`: public callback base URL

Example:

```bash
sam-hub \
  --issuer https://issuer.example.com \
  --client-id sam-client \
  --client-secret sam-secret \
  --key $(openssl rand -hex 32)
```
