# Testnet & Mesh Validation Tutorial

This tutorial guides you through validating your local environment integration with the public Sovereign Agent Mesh (SAM) testnets (`bananas.sam-mesh.dev` or `hub.sam-mesh.dev`). You will learn how to verify your node's connection, discover remote MCP services, and invoke remote tools.

---

## Prerequisites

Before starting, ensure you have:
1. Compiled the local binaries (`sam-node` and `mcp-client`) by running:
   ```bash
   make build
   ```
2. An active local `sam-node` container or process running and successfully joined to the target public testnet.
   For example, join via:
   ```bash
   bin/sam-node join https://bananas.sam-mesh.dev
   ```
   And run via:
   ```bash
   docker run --name sam-node \
     -v ~/.config/sam-mesh:/data \
     -p 5001:5001/udp -p 5002:5002 -p 8080:8080 \
     sam-node:local \
     run --data-dir /data \
       --hub https://bananas.sam-mesh.dev \
       --bind-addr 0.0.0.0:8080 \
       --api-token secret-token \
       --log-level debug
   ```

---

## Step 1: Verifying Local Connection to the Testnet

Check the logs of your local `sam-node` to ensure it has successfully joined and is online:
```text
INFO  sam-node  [AuthN] Successfully authenticated with hub via libp2p
SAM Node Online.
PeerID: 12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR
```

---

## Step 2: Discovering Remote Services on the Testnet

Use the local `mcp-client` binary against your local node to discover active services of type `mcp` on the public testnet:

```bash
bin/mcp-client -url http://localhost:8080 -stream -token secret-token -args '{"type":"mcp"}'
```

You will see discovered remote peer details in real-time, including proxy endpoint URLs for any running canary/test replicas on GKE:
```json
{"peer_id":"12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR","local_proxy_url":"http://[::]:8080/sam/12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR/mcp/everything","srv_name":"everything","srv_description":"MCP everything test server"}
```
Note down the remote `peer_id` of the service you want to target (e.g. `everything` or `openclaw`).

---

## Step 3: Invoking Tools via the Control Plane

You can invoke control plane tools on your local `sam-node` to locate, query, and invoke remote tools.

### List Local Control Plane Tools
```bash
bin/mcp-client -url http://localhost:8080/mcp/events -token secret-token -list
```

### Find Remote Tools on a Specific Peer
```bash
bin/mcp-client -url http://localhost:8080/mcp/events -token secret-token -tool find_remote_tools -args '{"peer_id":"12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR"}'
```
This returns the list of available tools (e.g., `everything.get-sum`, `everything.echo`).

### Inspect Tool Schemas
```bash
bin/mcp-client -url http://localhost:8080/mcp/events -token secret-token -tool describe_remote_tool -args '{"peer_id":"12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR", "tool_name":"everything.get-sum"}'
```

### Call the Remote Tool
```bash
bin/mcp-client -url http://localhost:8080/mcp/events -token secret-token -tool call_remote_tool -args '{"peer_id":"12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR", "tool_name":"everything.get-sum", "arguments":{"a":37.5, "b":5.2}}'
```
Response:
```text
The sum of 37.5 and 5.2 is 42.7.
```

---

## Step 4: Bypassing the Control Plane (HTTP Proxy & Streamable HTTP)

The `sam-node` includes an HTTP reverse proxy endpoint at `/sam/` which maps raw HTTP calls over P2P streams to the target service. For services using the **Streamable HTTP** transport, you can manage sessions and retrieve resources directly:

### 1. Initialize a Streamable Session
Initiate a handshake by sending a POST `initialize` JSON-RPC request. You must supply both `Accept` and `Mcp-Session-Id` headers to satisfy the transport:

```bash
curl -i -X POST \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0.0"}}}' \
  http://localhost:8080/sam/12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR/mcp/everything/
```

Observe the response headers. The server returns a session ID:
```http
HTTP/1.1 200 OK
Mcp-Session-Id: 4616e90e-a1a9-4953-b7d3-6884ff502472
Content-Type: text/event-stream
```

### 2. List Remote Resources
Use the returned session ID to query the remote service's resource list:

```bash
curl -s -X POST \
  -H "Authorization: Bearer secret-token" \
  -H "Mcp-Session-Id: 4616e90e-a1a9-4953-b7d3-6884ff502472" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/list"}' \
  http://localhost:8080/sam/12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR/mcp/everything/
```

### 3. Read Resource Content
Request the contents of a specific resource URI (e.g. `demo://resource/static/document/features.md`):

```bash
curl -s -X POST \
  -H "Authorization: Bearer secret-token" \
  -H "Mcp-Session-Id: 4616e90e-a1a9-4953-b7d3-6884ff502472" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"demo://resource/static/document/features.md"}}' \
  http://localhost:8080/sam/12D3KooWKquLDsMiFc5BXsaHmVoJLDDGddqEWbVYYCpUnHR9u6RR/mcp/everything/
```
