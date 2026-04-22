# Hub Key Management

The SAM hub manages two types of Ed25519 keys:

1. **Signing Key**: Used to digitally sign identity biscuits (passports)
2. **Identity/TLS Key**: Used for the hub's libp2p peer identity and TLS handshakes (when running with `--enable-p2p`)

## Key Generation

Generate both keys:

```bash
sam-hub keygen --with-identity
```

Output example:

```
=== Passport Signing Key (Ed25519) ===
Purpose: Sign identity biscuits
Environment: SAM_HUB_KEY

Private Key (base64):
4XkwpAJ0C9vqXkL...

Public Key (base64, published at /.well-known/sam-hub-keys):
GvK2pxM9d3sY8zL...

=== Hub Peer Identity Key (Ed25519 for libp2p TLS) ===
Purpose: Hub's libp2p peer identity and TLS handshakes
Environment: SAM_HUB_IDENTITY_KEY

Private Key (base64):
AwV3dY7pQ4sL2xN...

Public Key (base64):
B1Z5cX8mR6wL3yO...

Hub Peer ID: Use 'sam-hub serve --enable-p2p' to print the peer ID
Configure as bootstrap: --bootstrap /ip4/HUB_IP/udp/PORT/quic-v1/p2p/PEER_ID
```

## Configuration

### HTTP-Only Mode (No libp2p)

Suitable for cloud deployments behind a load balancer:

```bash
# Development (uses deterministic seed)
sam-hub serve --http-listen :8081

# Production (with custom signing key)
export SAM_HUB_KEY="4XkwpAJ0C9vqXkL..."
sam-hub serve --http-listen 0.0.0.0:8081
```

### P2P Rendezvous Mode

Enable the hub as a DHT bootstrap/rendezvous point:

```bash
# Development (generates ephemeral peer identity)
sam-hub serve --enable-p2p

# Production (with configured keys)
export SAM_HUB_KEY="4XkwpAJ0C9vqXkL..."
export SAM_HUB_IDENTITY_KEY="AwV3dY7pQ4sL2xN..."
sam-hub serve \
  --http-listen 0.0.0.0:8081 \
  --p2p-listen /ip4/0.0.0.0/udp/9000/quic-v1,/ip4/0.0.0.0/tcp/9001 \
  --enable-p2p
```

After startup, the hub prints its peer ID and multiaddrs:

```
=== libp2p Host ===
Peer ID: 12D3KooWJqYwgPjYqC6Y3...

Multiaddrs:
  /ip4/10.0.0.5/udp/9000/quic-v1/p2p/12D3KooWJqYwgPjYqC6Y3...
  /ip4/10.0.0.5/tcp/9001/p2p/12D3KooWJqYwgPjYqC6Y3...
```

Share these with agents as bootstrap peers.

## Key Rotation

### Signing Key Rotation

When rotating the signing key:

1. Generate a new key: `sam-hub keygen`
2. Update `SAM_HUB_KEY` in your deployment
3. Restart the hub gracefully
4. Agents automatically fetch the new public key from `/.well-known/sam-hub-keys`

Existing passports remain valid (keep the old key for verification if needed).

### Identity Key Rotation

When rotating the libp2p identity key:

1. Generate a new key: `sam-hub keygen --with-identity`
2. Update `SAM_HUB_IDENTITY_KEY` in your deployment
3. Restart the hub
4. Update agent bootstrap peer configuration with the new peer ID and multiaddrs

This changes the hub's peer ID, so agents must reconfigure.

## Security Practices

### Key Storage

- **Use secrets management**: Kubernetes Secrets, AWS Secrets Manager, HashiCorp Vault, etc.
- **Encrypt at rest**: Ensure key material is encrypted when stored
- **Restrict access**: Only the hub process should have access to private keys
- **Audit logging**: Log all key operations and passport issuance

Example Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sam-hub-keys
type: Opaque
stringData:
  SAM_HUB_KEY: |
    4XkwpAJ0C9vqXkL...
  SAM_HUB_IDENTITY_KEY: |
    AwV3dY7pQ4sL2xN...
```

### Key Rotation Schedule

- **Signing key**: Rotate annually or after suspected compromise
- **Identity key**: Rotate on topology changes or annually
- **Emergency rotation**: If a key is suspected compromised, rotate immediately

### TLS Specifics

libp2p uses **certificate-based TLS** with Ed25519 keys:
- The private key signs the TLS certificate
- Certificates are self-signed and ephemeral
- The public key is derived from the private key
- No external CA or X.509 infrastructure needed

For **FIPS compliance**, ensure Go is compiled with `GOEXPERIMENT=boringcrypto` and libp2p's TLS security transport is the only configured security transport.

## Client-Side Verification

Agents verify biscuit signatures using the hub's public signing key. The key is published at:

```bash
curl https://hub.example.com/.well-known/sam-hub-keys
```

Response:

```json
{
  "issuer": "app.sam-mesh.dev",
  "keys": [
    {
      "kid": "sam-hub-root-v1",
      "alg": "Ed25519",
      "k": "GvK2pxM9d3sY8zL..."
    }
  ]
}
```

Clients cache this public key for offline verification without requiring network calls.

## Troubleshooting

### Invalid Key Format

Error: `decoding SAM_HUB_KEY: illegal base64 data at input byte`

- Ensure keys are base64url-encoded (no padding)
- Use `sam-hub keygen` to generate properly formatted keys

### Peer ID Mismatch

Error: `passport peer mismatch` or `passport authentication failed`

- Verify the hub is using the correct signing key
- Ensure all hub instances (if load-balanced) use the same signing key
- Check agents are fetching the correct public key from `/.well-known/sam-hub-keys`

### Bootstrap Connection Failed

Error: `connecting to hub bootstrap peer: ...`

- Verify the peer ID and multiaddrs are correct
- Check hub is reachable at the advertised address
- Ensure TLS/QUIC connections are not blocked by firewalls

## Integration with Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sam-hub-keys
type: Opaque
stringData:
  SAM_HUB_KEY: 4XkwpAJ0C9vqXkL...
  SAM_HUB_IDENTITY_KEY: AwV3dY7pQ4sL2xN...

---

apiVersion: apps/v1
kind: Deployment
metadata:
  name: sam-hub
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: hub
        image: sam-hub:latest
        args:
          - serve
          - --http-listen=0.0.0.0:8081
          - --p2p-listen=/ip4/0.0.0.0/udp/9000/quic-v1,/ip4/0.0.0.0/tcp/9001
          - --enable-p2p
        env:
        - name: SAM_HUB_KEY
          valueFrom:
            secretKeyRef:
              name: sam-hub-keys
              key: SAM_HUB_KEY
        - name: SAM_HUB_IDENTITY_KEY
          valueFrom:
            secretKeyRef:
              name: sam-hub-keys
              key: SAM_HUB_IDENTITY_KEY
        ports:
        - containerPort: 8081
          name: http
        - containerPort: 9000
          protocol: UDP
          name: p2p-quic
        - containerPort: 9001
          name: p2p-tcp
```
