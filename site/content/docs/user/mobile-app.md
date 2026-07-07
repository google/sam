---
title: "SAM Mobile App (Android/iOS)"
linkTitle: "Mobile App"
weight: 5
---

# SAM Node Mobile (Flutter Client)

The SAM Mobile App is a Flutter application that packages and runs the native Go-based `sam-node` mesh client on mobile devices using Go's CGO compiler and Dart FFI (Foreign Function Interface).

It allows you to turn your phone into a fully functional node in the Sovereign Agent Mesh, exposing device sensors and capabilities securely to AI agents.

---

## Features & Capabilities

### 📱 1. Embedded MCP Server & Real Telemetry
The app includes an embedded MCP server that exposes real-time telemetry from your device:
*   **Battery Status**: Level and charging state.
*   **Location**: Coarse/Fine coordinates (requires permissions).
*   **Foreground Service**: Keeps the node alive and connected even when the phone is idle or backgrounded (Android 14+ compatible).

### 🤖 2. Android 16 AppFunctions (On-Device MCP)
Exposes capabilities directly to the OS registry, allowing native assistants (like Gemini) to orchestrate tasks without manual app navigation.
*   `getMeshStatus`: Returns node stats and connected peers.
*   `callRemoteMeshTool`: Proxy to invoke tools on remote mesh peers.

---

## Screenshots

| Node Status / Dashboard | Services & Telemetry |
|:---:|:---:|
| ![Node Logged](/images/mobile_node_logged.png) | ![Services Enabled](/images/mobile_services_enabled.png) |

---

## How to Use the Application

1.  **Enrollment**: Enter the **Hub URL** (e.g., `https://bananas.sam-mesh.dev`) and your **Enrollment JWT**.
2.  **API Token**: Set a local API token (defaults to `secret-token`) to secure local access.
3.  **Start Node**: Launches the background Go node runtime.
4.  **Dashboard**: Monitor connected peers and DHT size.
5.  **Services Tab**: Enable/Disable embedded sensors (Battery/Location) to expose them to the mesh.

---

## Developer Integration & Usage Examples

### Option 1: CLI Usage (Technical Verification)

You can query the phone's telemetry from a remote machine (or another node) using the repository's `mcp-client` utility.

1.  **Discover tools on the remote phone service**:
    ```bash
    # Query the local SAM node proxy for tools hosted by the phone-sensors peer
    go run cmd/mcp-client/main.go \
      -url "http://localhost:8080/sam/<PHONE_PEER_ID>/mcp/phone-sensors" \
      -token "secret-token" \
      -list
    ```
    *Output:*
    *   `get_battery_status`: Returns the current battery level and charging status of the device.
    *   `get_location`: Returns the current coarse location of the device.

2.  **Query the location**:
    ```bash
    go run cmd/mcp-client/main.go \
      -url "http://localhost:8080/sam/<PHONE_PEER_ID>/mcp/phone-sensors" \
      -token "secret-token" \
      -tool "get_location"
    ```
    *Output:* `{"latitude": 42.2805588, "longitude": -8.6124088}`

---

### Option 2: AI Agent Interaction Flow

Clean, successful flow of an AI agent discovering and querying the mesh.

| Step | Action | Details / Tool | Result |
|---|---|---|---|
| 1 | Discover Peers & Tools | `find_remote_tools` | Found peer `<PHONE_PEER_ID>` hosting service `phone-sensors` with tool `mcp://phone-sensors/get_location`. |
| 2 | Verify Schema | `describe_remote_tool` | Confirmed `get_location` requires no input parameters: `{"input_schema": {"type": "object", "properties": {}}}`. |
| 3 | Query Location | `call_remote_tool` | Received: `{"latitude": 42.2805588, "longitude": -8.6124088}` |
| 4 | Resolve Address | Web Search | Geolocated to Vigo / Redondela area, Galicia, Spain. |

---

## Compilation Instructions

For instructions on how to build the application from source, please refer to the [Mobile App README](https://github.com/google/sam/tree/main/mobile/sam-node-app).
