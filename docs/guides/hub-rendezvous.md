# Hub as Rendezvous Point

SAM uses the configured hub's hostname as the discovery namespace scope for peer capability advertisements. This enables:

1. **Capability Namespace Scoping**: All peer capability announcements are registered under `<hub-hostname>/<capability>` in the DHT.
2. **Centralized Discovery Index**: When agents discover peers by capability, they query the DHT for records under the hub's namespace.
3. **Bootstrap Topology**: To make the hub act as an active rendezvous point, configure it as a bootstrap peer so all agents connect to it during startup.

## Configuration

### CLI Usage

Set the hub and optionally bootstrap peers:

```bash
sam-agent up \
  --hub https://identity.example.com \
  --bootstrap /ip4/<hub-ip>/udp/0/quic-v1/p2p/<hub-peer-id> \
  ...
```

When `--hub` is provided without an explicit bootstrap address, the CLI uses the hub's hostname as the rendezvous namespace default.

### Programmatic Usage

```go
import samnet "sam/pkg/net"

// Hub hostname becomes the rendezvous namespace
node, err := samnet.New(
  samnet.WithRendezvousNamespace("identity.example.com"),
  samnet.WithBootstrapPeers(/* hub peer multiaddr */),
  // ...
)
```

## Hub Architecture

The hub (sam-hub) currently provides:
- HTTP endpoint for passport issuance (`:8081/issue-passport`)
- Health and metadata endpoints
- Future: optional libp2p host for direct rendezvous protocol support

To upgrade the hub to a full rendezvous server:
1. Add a libp2p host to sam-hub/main.go
2. Export the hub's peer ID and addresses for agent bootstrap configuration
3. Implement rendezvous protocol handlers for registration/discovery

## Discovery Flow

```
Agent A:
  1. Connect to hub (bootstrap peer)
  2. Announce capability: /sam/fed/default/<hub-hostname>/my-skill
  
Agent B:
  1. Connect to hub (bootstrap peer)
  2. Discover capability: /sam/fed/default/<hub-hostname>/my-skill
  3. Find Agent A in DHT results
  4. Connect and authenticate via /sam/auth/1.0.0
```
