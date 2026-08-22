---
title: "Sandbox Gateway Guide"
linkTitle: "Sandbox Gateway"
weight: 30
---

`sam-box` is the sandbox gateway: one per agent sandbox, serving the boundary an
agent's traffic leaves through. An unmodified agent reaches mesh inference and
tools by name, reaches allowlisted destinations on the internet, and reaches
nothing else.

For the reasoning behind the design, see
[Agent Architecture]({{< relref "/docs/agent-architecture" >}}).

---

## 1. What it is, and is not

`sam-box` holds **no libp2p host, no enrolment and no mesh identity**. It
consumes a local `sam-node` over that node's API socket, and offers the sandbox
a curated surface built on top of it.

```mermaid
sequenceDiagram
    participant Agent as Agent (inside the sandbox)
    participant Box as sam-box (sandbox boundary)
    participant Node as sam-node (mesh member)
    participant Mesh as The mesh / the internet

    Agent->>Box: SOCKS5 CONNECT mesh.sam.alt:80
    Box->>Box: Classify by name, apply policy
    Box->>Node: /v1/chat/completions over the node's API socket
    Node->>Mesh: Route to a provider, authorized by the node's Biscuit
    Mesh-->>Agent: Response
```

The split matters. A `sam-node`'s API can register services under the node's
identity and proxy to any peer, and reaching its socket is itself the
credential. So an agent never touches it: `sam-box` is the node's consumer, the
agent is the mesh's consumer through `sam-box`.

---

## 2. Running it

```bash
sam-box run \
  --socket=/var/run/sam/agent.sock \
  --sidecar-socket=/var/run/sam/node.sock \
  --egress-allow=api.github.com \
  --egress-allow='*.pypi.org'
```

| Flag | Meaning |
|---|---|
| `--socket` | The sandbox-facing socket. Created 0600: its permissions are the credential. |
| `--sidecar-socket` | The local `sam-node`'s API socket (`sam-node run --socket-path`). |
| `--bundle` | The agent's identity and egress allowance, declared by the platform. |
| `--egress-allow` | A destination outside the mesh the agent may reach. Repeatable. **Empty means nothing is reachable.** |
| `--credential-issuer`, `--credential-audience` | The issuer whose credentials attest an agent's identity. **Required with `--bundle`.** |
| `--insecure-unverified-bundle` | Trust the bundle without a credential behind it. An explicit choice, not a default. |

Egress entries are matched on the name the agent asked for, never on a resolved
address. A wildcard covers subdomains only: `*.pypi.org` matches
`files.pypi.org` but not `pypi.org`, and never `evilpypi.org`.

A bundle names an agent, and that name is what the whole mesh then authorizes
against — so by default it has to be backed by the credential the platform
issued to that workload. Running without that check is available, because some
deployments have no platform issuer, but it takes a flag that is visible in a
process listing and a pod spec rather than something quietly left unset.

The issuer is a flag rather than a bundle field on purpose: the bundle travels
with the agent, so an issuer named there could be one an attacker controls, and
their self-signed credential would verify perfectly.

---

## 3. What the agent sees

```bash
OPENAI_BASE_URL=http://mesh.sam.alt/v1
MCP_URL=http://mesh.sam.alt/mcp
```

No proxy variables, no CA bundle, no token: the agent holds no credential at
all. `mesh.sam.alt` serves exactly four paths — `/v1/models`,
`/v1/chat/completions`, `/v1/completions` and `/mcp`. Anything else is refused
with 403 and never reaches the node.

A specific service can be addressed by its own name instead of letting policy
choose: `http://code-reviewer.mcp.sam.alt/`.

Destinations that policy refuses fail the SOCKS5 handshake, which the sandbox's
kernel turns into an ordinary connection refusal — so an agent sees "refused"
rather than a hang.

---

## 4. Connecting a sandbox to the socket

The sandbox has no network of its own. It runs `tun2socks` against a `tun`
device and points it at the boundary socket, so every flow leaves as SOCKS5
carrying the destination *name*:

| sandbox | how it reaches the socket |
|---|---|
| Firecracker microVM | vsock; firecracker terminates it as `<uds_path>_<port>` on the host |
| container with `network=none` | the socket is bind-mounted in |

For a quick test without a sandbox, bridge a TCP port to the socket and use any
SOCKS5 client:

```bash
socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:/var/run/sam/agent.sock &
curl --socks5-hostname 127.0.0.1:1080 http://mesh.sam.alt/v1/models
```

---

## 5. Serving a mesh service

An agent can serve, not only call. Its bundle says what it is allowed to serve;
the agent itself says when it is ready and on which port:

```yaml
ingress:
  - {name: code-reviewer, type: mcp}
```

```bash
curl -X POST http://mesh.sam.alt/ingress \
  -d '{"name":"code-reviewer","type":"mcp","port":8080}'
```

The gateway then registers the service with the node. The agent never does: it
cannot name the URL the mesh routes to, and it cannot claim a name its bundle
does not list. When the gateway stops, the service is withdrawn, so a suspended
agent stops being advertised without anyone reconciling anything.

Reaching back into the sandbox cannot mean dialling the agent: a sandbox has a
network namespace of its own, so the gateway's `127.0.0.1` is its own loopback
and not the agent's. Delivery therefore goes over a second Unix socket, served
from inside the sandbox by `nano-init --ingress-socket` and dialled by
`sam-box --agent-ingress-socket`. That flag is required whenever a bundle grants
ingress: the gateway refuses to start without it, because the only other address
available is one in its own network namespace, on a port the agent chooses.

---

## 6. Not yet implemented

Deliberately absent, and tracked in the architecture document:

* **Secret injection** for external destinations. The ephemeral CA and the
  injection machinery exist, but are not wired into this datapath.
* **The ingress reverse channel**, for sandboxes the gateway cannot dial.
* **Credential rotation.** A bundle's credential is verified when the gateway
  starts. Platforms rotate projected tokens, and re-verifying on rotation is
  the connector interface's `Refresh` operation, which is not built yet.
