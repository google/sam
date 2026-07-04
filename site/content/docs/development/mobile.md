---
title: "Mobile Support (Android & iOS)"
linkTitle: "Mobile Support"
weight: 6
---

This guide describes the architecture, compilation toolchain, development workflow, and testing procedures for running `sam-node` on mobile platforms (Android and iOS).

---

## Architecture Overview

To run `sam-node` on mobile with near-zero codebase maintenance, we avoid rewriting the p2p network stack and routing logic in Kotlin/Swift. Instead, we use Go's CGO compiler to generate native C-compatible libraries that are loaded and controlled inside a Flutter app using **Dart FFI (Foreign Function Interface)**.

```
       ┌────────────────────────────────────────────────────────┐
       │                   Flutter Mobile App                   │
       │                                                        │
       │  ┌─────────────────┐             ┌──────────────────┐  │
       │  │    Dart GUI     │             │  Dart FFI Client │  │
       │  └────────┬────────┘             └────────┬─────────┘  │
       │           │                               │            │
       └───────────┼───────────────────────────────┼────────────┘
                   │                               │ (C Function Calls)
                   │ (HTTP / JSON RPC)             ▼
       ┌───────────┼───────────────────────────────┼────────────┐
       │           ▼                               │            │
       │  ┌─────────────────┐             ┌────────▼─────────┐  │
       │  │   Sidecar API   │             │   Go FFI Entry   │  │
       │  │  (127.0.0.1)    │             │  (sam-node-ffi)  │  │
       │  └────────┬────────┘             └────────┬─────────┘  │
       │           │                               │ (Go APIs)  │
       │           ▼                               ▼            │
       │  ┌──────────────────────────────────────────────────┐  │
       │  │                     sam-node                     │  │
       │  └──────────────────────────────────────────────────┘  │
       │                      Go Runtime                        │
       └────────────────────────────────────────────────────────┘
```

1. **Go FFI Binding Package (`mobile/sam-node-ffi/`)**: Contains CGO-exported functions (`StartNode`, `StopNode`, `EnrollNode`, `GetNodeID`, `FreeString`) which compile into a C-shared library (`.so`) or static archive (`.a`).
2. **Flutter App (`mobile/sam-node-app/`)**: A cross-platform app containing:
   - `lib/sam_ffi.dart`: The Dart FFI wrapper loading the Go library and exposing Dart methods.
   - `lib/main.dart`: Simple control UI to enroll and start/stop the background node.
3. **Local Loopback Communication**:
   - The Flutter Dart environment controls the node lifecycle (construction, starting, stopping) via FFI.
   - Any actual tool registration, discovery, or mesh API queries are performed using standard HTTP JSON-RPC calls over local loopback (`127.0.0.1`) to the `sam-node` sidecar API.

---

## Make Build Targets

We provide dedicated `Makefile` targets to automate Go FFI compilation and copy binaries into the mobile app:

### 1. Build Host FFI (For local desktop testing)
Compiles `bin/libsam.so` for the host platform:
```bash
make mobile-ffi-host
```

### 2. Build Android FFI Library
Compiles `bin/android/libsam.so` targeting Android ARM64 devices:
```bash
make mobile-ffi-android
```

### 3. Build iOS FFI Library
Compiles `bin/ios/libsam.a` targeting iOS ARM64 devices:
```bash
make mobile-ffi-ios
```

### 4. Build Complete Android Release APK
Compiles the FFI library, bundles it inside the Flutter project, and builds the final release APK:
```bash
make mobile-app-apk
```

---

## Local Development Workflow

To make changes to `sam-node` and run them on a mobile device:

### Android Setup
1. Compile the Android ARM64 FFI shared library:
   ```bash
   make mobile-ffi-android
   ```
2. Copy the library into the Android project's `jniLibs` directory:
   ```bash
   mkdir -p mobile/sam-node-app/android/app/src/main/jniLibs/arm64-v8a
   cp bin/android/libsam.so mobile/sam-node-app/android/app/src/main/jniLibs/arm64-v8a/libsam.so
   ```
3. Connect your Android device via USB (verify connection with `adb devices`).
4. Run the app:
   ```bash
   cd mobile/sam-node-app
   flutter run
   ```

---

## Integration Testing (E2E)

We automate end-to-end integration verification in the CI by running a headless Android Emulator and executing bidirectional MCP discovery:

### Local Execution of E2E Script
If you have an active emulator running locally, you can run the full E2E orchestration test:
```bash
./mobile/mobile_e2e.sh
```

#### What the E2E test validates:
1. Starts a local **Mock OIDC Server** and **sam-hub** process on the host.
2. Registers a dummy tool (`host-tool`) on a host-level **sam-node**.
3. Boots the **Android Emulator**, installs the FFI-embedded app, and starts the node inside the emulator.
4. Registers an `emulator-tool` inside the emulator app.
5. Asserts **bidirectional discovery**:
   - The emulator app successfully discovers the host's `host-tool` via the mesh.
   - The host node successfully discovers the emulator's `emulator-tool` via the mesh.
6. Terminates all background processes and cleans up directories on completion.
