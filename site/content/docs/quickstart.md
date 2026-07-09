---
title: "Quick Start"
linkTitle: "Quick Start"
weight: 1
---

This guide gets you up and running with a SAM node connected to the public `bananas.sam-mesh.dev` mesh. You can run SAM either directly via a binary or using Docker.

## 1. Install SAM

### Option A: Install Script (macOS / Linux)
The easiest way to install the latest binaries directly:
```bash
curl -sL https://sam-mesh.dev/install.sh | bash
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

## 2. Connect Your Node to the Mesh

Getting a node onto the mesh takes two actions: **joining** — registering your node with the mesh and obtaining its cryptographic identity (Biscuit) through an OIDC login — and **running** it, which starts the node and connects it to the hub. The `--join` flag on `run` does both at once: it enrolls the node the first time (when it has no identity yet), then starts running it.

### One Command

#### Using the Binary
```bash
sam-node run --join --bind-addr 127.0.0.1:8080 --api-token my-secret-token
```

#### Using Docker
```bash
mkdir -p $(pwd)/sam-data
docker run -it \
  -v $(pwd)/sam-data:/data \
  -p 5001:5001/udp \
  -p 5002:5002 \
  -p 8080:8080 \
  ghcr.io/google/sam-node:latest \
  run --join --data-dir /data --bind-addr 0.0.0.0:8080 --api-token my-secret-token
```
The first run uses `-it` so you can complete the interactive login; once enrolled, you can restart it detached with `-d`.

By default this joins the public testnet (`bananas.sam-mesh.dev`); pass `--hub <url>` to enroll with a different mesh. On later restarts `--join` is ignored, since the identity is already stored, so it is safe to leave in your start command. If there is no interactive terminal to complete the login (for example a container started without `-it`), the node comes up unauthenticated so you can enroll separately.

You can also perform the two actions separately — the steps below cover each in more detail.

### Step 1: Join the Mesh

To register your node with the mesh and obtain a cryptographic identity token (Biscuit), run the OIDC authorization flow.

#### Using the Binary
```bash
sam-node join https://bananas.sam-mesh.dev
```

#### Using Docker
Create a local directory to persist your node identity:
```bash
mkdir -p $(pwd)/sam-data
docker run -it \
  -v $(pwd)/sam-data:/data \
  ghcr.io/google/sam-node:latest \
  join --data-dir /data https://bananas.sam-mesh.dev
```

The CLI will output a Device Authorization URL (if headless/Docker) or open your browser (if using the binary natively). Once authenticated, the node registers and saves the identity to `~/.config/sam-mesh/agent.db` (or `/data/agent.db` in Docker).

### Step 2: Run the Node

Start your node in the background. We set a security `--api-token` to protect access to the local control plane API.

#### Using the Binary
```bash
sam-node run --bind-addr 127.0.0.1:8080 --api-token my-secret-token
```
You should see in the logs:
```text
INFO  sam-node  [AuthN] Successfully authenticated with hub via libp2p: ...
SAM Node Online.
PeerID: 12D3KooW...
```

#### Using Docker
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

---

## 3. Query the Local MCP API

Your SAM node exposes a standard Model Context Protocol (MCP) server. The easiest way to interact with it is using the `mcp-client` CLI tool (which is installed alongside `sam-node`):

### List Local Control Plane Tools
Query the list of tools available on your local node (e.g. peer discovery, message broadcast, and remote tool execution):

```bash
mcp-client -url http://localhost:8080/mcp -token my-secret-token -list
```

### Discover Remote Services in the Mesh
List active MCP services currently registered across the public mesh network:

```bash
mcp-client -url http://localhost:8080/mcp \
  -tool discover_remote_services \
  -args '{"type":"mcp"}'
```

### Find Remote Tools on a Peer
Using a `peer_id` returned from the service discovery, find the tools available on that peer:

```bash
mcp-client -url http://localhost:8080/mcp \
  -tool find_remote_tools \
  -args '{"peer_id":"<target-peer-id>"}'
```

### Call a Remote Tool
Call a tool hosted on a remote peer through your local node's P2P stream reverse proxy:

```bash
mcp-client -url http://localhost:8080/mcp \
  -tool call_remote_tool \
  -args '{"peer_id":"<target-peer-id>","tool_name":"everything.get-sum","arguments":{"a":12.5,"b":7.5}}'
```
