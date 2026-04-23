# CLI Reference

The current repository exposes two CLIs:

- `sam-node`
- `sam-hub`

## sam-node

```bash
sam-node --help
```

### sam-node login

Start the login flow and persist identity biscuit in the local store.

```bash
sam-node login --hub http://localhost:8080
```

Flags:

- `--hub`: hub base URL (default `http://localhost:8080`)

### sam-node run

Start the mesh node.

```bash
sam-node run
```

Flags:

- `--token`: identity biscuit override (if omitted, load from local store)
- `--listen`: repeatable libp2p listen addresses

Examples:

```bash
sam-node run --token <identity-biscuit>
sam-node run --listen /ip4/0.0.0.0/udp/5001/quic-v1 --listen /ip4/0.0.0.0/tcp/5002
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
