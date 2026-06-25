# Quick Start

This guide gets you up and running with a SAM node connected to the public `bananas.sam-mesh.dev` mesh using Docker.

---

## 1. Join the Mesh

To register your node with the mesh and obtain a cryptographic identity token (Biscuit), run the OIDC device authorization flow. 

Create a local directory on your host to persist your node identity:

```bash
mkdir -p $(pwd)/sam-data
```

Enroll your node:

```bash
docker run -it \
  -v $(pwd)/sam-data:/data \
  ghcr.io/google/sam-node:latest \
  join --data-dir /data https://bananas.sam-mesh.dev
```

1. The container will output a Device Authorization URL and a validation code.
2. Open the URL in your web browser and sign in.
3. Once authenticated, the container registers the node, saves the identity to `/data/agent.db` (persisted on your host at `./sam-data/agent.db`), and exits.

---

## 2. Run the Node

Start your node in the background. We set a security `--api-token` to protect access to the local control plane API and map the required ports:

- `5001/udp` and `5002/tcp`: Libp2p swarm connection ports.
- `8080/tcp`: Local MCP SSE HTTP API.

```bash
docker run -d \
  --name sam-node \
  -v $(pwd)/sam-data:/data \
  -p 5001:5001/udp \
  -p 5002:5002 \
  -p 8080:8080 \
  ghcr.io/google/sam-node:latest \
  run --data-dir /data --bind-addr 0.0.0.0:8080 --api-token my-secret-token
```

To verify the node is running and connected to the testnet, check the logs:

```bash
docker logs sam-node
```

You should see:
```text
INFO  sam-node  [AuthN] Successfully authenticated with hub via libp2p: ...
SAM Node Online.
PeerID: 12D3KooW...
```

---

## 3. Query the Local MCP API

Your SAM node exposes a standard Model Context Protocol (MCP) server over HTTP Server-Sent Events (SSE) at `http://localhost:8080/mcp/message`. You can interact with it using simple `curl` commands.

### List Local Control Plane Tools
Query the list of tools available on your local node (e.g. peer discovery, message broadcast, and remote tool execution):

```bash
curl -X POST \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' \
  http://localhost:8080/mcp/message
```

### Discover Remote Services in the Mesh
List active MCP services currently registered across the public mesh network:

```bash
curl -X POST \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"discover_remote_services","arguments":{"type":"mcp"}},"id":2}' \
  http://localhost:8080/mcp/message
```

### Find Remote Tools on a Peer
Using a `peer_id` returned from the service discovery, find the tools available on that peer:

```bash
curl -X POST \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"find_remote_tools","arguments":{"peer_id":"<target-peer-id>"}},"id":3}' \
  http://localhost:8080/mcp/message
```

### Call a Remote Tool
Call a tool hosted on a remote peer through your local node's P2P stream reverse proxy:

```bash
curl -X POST \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"call_remote_tool","arguments":{"peer_id":"<target-peer-id>","tool_name":"everything.get-sum","arguments":{"a":12.5,"b":7.5}}},"id":4}' \
  http://localhost:8080/mcp/message
```
