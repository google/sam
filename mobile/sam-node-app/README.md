# SAM Node Mobile (Flutter Client)

This folder contains a Flutter application that packages and runs the native Go-based `sam-node` mesh client on mobile devices (Android and iOS) using Go's CGO compiler and Dart FFI (Foreign Function Interface).

---

## Architecture Overview

The app compiles the core Go mesh networking and routing logic into a C-compatible shared library (`.so` or `.a`), which is loaded dynamically by the Dart runtime. The Dart GUI manages the lifecycle of the node (enrollment, start, stop) via FFI function calls, while any tool registration, discovery, or mesh API queries are sent via standard HTTP JSON-RPC to the local loopback port of the node's sidecar server.

---

## Prerequisites

Before building the application, ensure you have configured:
1. **Flutter SDK**: Installed and configured (run `flutter doctor` to verify).
2. **Go Compiler**: Version 1.26+ installed.
3. **Android NDK**: Required to cross-compile the Go library for Android platforms. Ensure the `ANDROID_NDK_HOME` environment variable points to your NDK installation.
4. **Xcode**: (iOS only) Installed and configured for iOS compile targets.

---

## Compilation Instructions

To build the app, you must first compile the Go FFI library and bundle it inside the Flutter project:

### 1. Compile FFI Library

Run one of the following commands from the **repository root directory**:

*   **For Android ARM64 Devices (Physical Phones)**:
    ```bash
    make mobile-ffi-android
    ```
    *Copies the binary to `mobile/sam-node-app/android/app/src/main/jniLibs/arm64-v8a/libsam.so`*

*   **For Android x86_64 Emulators (AVD)**:
    ```bash
    make mobile-ffi-android-x86_64
    ```
    *Copies the binary to `mobile/sam-node-app/android/app/src/main/jniLibs/x86_64/libsam.so`*

*   **For iOS Devices**:
    ```bash
    make mobile-ffi-ios
    ```
    *Generates static archive `bin/ios/libsam.a`*

### 2. Run the App

Connect your device or start your emulator, then run:
```bash
cd mobile/sam-node-app
flutter run
```

---

## How to Use the Application

Once launched, the app displays a control interface:

1.  **Hub URL / Address**: The address of the SAM Hub (e.g., `https://bananas.sam-mesh.dev`).
2.  **Enrollment JWT**: A valid JWT token retrieved from your OIDC provider to authenticate the node registration.
3.  **Local API Token**: The secret bearer token used to secure the local sidecar REST APIs (defaults to `secret-token`).
4.  **Enroll Node**: Click this button first to generate the local Peer Identity and register the node with the Hub.
5.  **Start Node**: Launches the Go node runtime in the background. It will bind its local MCP sidecar to `127.0.0.1:5005`.
6.  **Stop Node**: Gracefully shuts down the background Go mesh client.

---

## Developer Integration & API Usage

Once the node is **Running**, other applications on the mobile device (or inside the emulator) can connect to its local HTTP API:

### 1. Model Context Protocol (MCP) Client
Connect a local agent client to the streamable SSE endpoint:
*   **SSE URL**: `http://127.0.0.1:5005/mcp`
*   **Headers**:
    *   `Authorization: Bearer <Local-API-Token>`
    *   `Accept: text/event-stream`

### 2. Registering Local Tools
An app on the device can expose its own tools to the mesh by registering them with the sidecar registry:
*   **POST URL**: `http://127.0.0.1:5005/sam/service/register`
*   **Headers**:
    *   `Authorization: Bearer <Local-API-Token>`
    *   `Content-Type: application/json`
*   **Body Example**:
    ```json
    {
      "service": {
        "type": "SERVICE_TYPE_MCP",
        "name": "my-mobile-tool",
        "description": "Exposes mobile device sensors/actions"
      },
      "targetUrl": "http://127.0.0.1:9090"
    }
    ```
