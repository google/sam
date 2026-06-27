---
title: "Quick Start"
linkTitle: "Quick Start"
weight: 10
---

# Quick Start

This guide gets you up and running with a SAM node connected to the public `bananas.sam-mesh.dev` mesh. You can run SAM either directly via a binary or using Docker.

## 1. Install SAM

### Option A: Install Script (macOS / Linux)
The easiest way to install the latest binaries directly:
```bash
curl -sL https://raw.githubusercontent.com/google/sam/main/install.sh | bash
```

### Option B: Go Install (macOS / Linux / Windows)
If you have Go installed, you can compile and install directly from the repository:
```bash
go install github.com/google/sam/cmd/sam-node@latest
go install github.com/google/sam/cmd/sam-hub@latest
```

### Option C: PowerShell (Windows)
For Windows users without WSL, you can download the latest release using PowerShell:
```powershell
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/google/sam/releases/latest"
$Version = $Release.tag_name
$Url = "https://github.com/google/sam/releases/download/$Version/sam_Windows_x86_64.zip"
Invoke-WebRequest -Uri $Url -OutFile "sam.zip"
Expand-Archive -Path "sam.zip" -DestinationPath "$env:ProgramFiles\sam"
```

---

## 2. Join the Mesh

To register your node with the mesh and obtain a cryptographic identity token (Biscuit), run the OIDC authorization flow. 

### Using the Binary
```bash
sam-node join https://bananas.sam-mesh.dev
```

### Using Docker
Create a local directory to persist your node identity:
```bash
mkdir -p $(pwd)/sam-data
docker run -it \
  -v $(pwd)/sam-data:/data \
  ghcr.io/google/sam-node:latest \
  join --data-dir /data https://bananas.sam-mesh.dev
```

The CLI will output a Device Authorization URL (if headless/Docker) or open your browser (if using the binary natively). Once authenticated, the node registers and saves the identity to `~/.config/sam-mesh/agent.db` (or `/data/agent.db` in Docker).

---

## 3. Run the Node

Start your node in the background. We set a security `--api-token` to protect access to the local control plane API.

### Using the Binary
```bash
sam-node run --bind-addr 127.0.0.1:8080 --api-token my-secret-token
```
You should see in the logs:
```text
INFO  sam-node  [AuthN] Successfully authenticated with hub via libp2p: ...
SAM Node Online.
PeerID: 12D3KooW...
```

### Using Docker
Map the required ports (`5001/udp`, `5002/tcp` for libp2p, and `8080/tcp` for the local API):
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
Verify the node is running with `docker logs sam-node`.

## 4. Query the Local MCP API

Your SAM node exposes a standard Model Context Protocol (MCP) server. The easiest way to interact with it is using the `mcp-client` CLI tool (which is installed alongside `sam-node`):

### List Local Control Plane Tools
Query the list of tools available on your local node (e.g. peer discovery, message broadcast, and remote tool execution):

```bash
mcp-client -url http://localhost:8080/mcp/events -token my-secret-token -list
```

### Discover Remote Services in the Mesh
List active MCP services currently registered across the public mesh network:

```bash
mcp-client -url http://localhost:8080/mcp/events \
  -tool discover_remote_services \
  -args '{"type":"mcp"}'
```

### Find Remote Tools on a Peer
Using a `peer_id` returned from the service discovery, find the tools available on that peer:

```bash
mcp-client -url http://localhost:8080/mcp/events \
  -tool find_remote_tools \
  -args '{"peer_id":"<target-peer-id>"}'
```

### Call a Remote Tool
Call a tool hosted on a remote peer through your local node's P2P stream reverse proxy:

```bash
mcp-client -url http://localhost:8080/mcp/events \
  -tool call_remote_tool \
  -args '{"peer_id":"<target-peer-id>","tool_name":"everything.get-sum","arguments":{"a":12.5,"b":7.5}}'
```
