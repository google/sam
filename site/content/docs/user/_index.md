---
title: "User and Operator Guides"
linkTitle: "User Guides"
weight: 3
---

Welcome to the User & Operator Guides. This section provides detailed documentation on how to configure, run, and manage Sovereign Agent Mesh (SAM) clusters, hubs, and node configurations.

### In This Section

1. **[Hub Configuration](hub-configuration/)**
   Learn how to configure the OIDC identity bridge, set up cryptographic private keys, enforce TLS/mTLS, and write custom security role policy mappings in `policies.yaml`.

2. **[Agent Usage & Connectivity](agent-usage/)**
   Understand how nodes connect to the mesh via OIDC login, secure credentials, run local Model Context Protocol (MCP) servers, and expose secure remote tool access to agents (like Google Gemini and Claude).

3. **[Node Configuration](node-configuration/)**
   Learn how to configure the local node, set up binding addresses, and manage local storage.

4. **[Production Kubernetes Deployment](kubernetes-deployment/)**
   Deploy a production-grade mesh cluster in Kubernetes, including Dex OIDC setups, StatefulSet P2P hubs, DNS A-record synchronizers, and Workload Identity ServiceAccount token projections.

5. **[SAM Mobile App](mobile-app/)**
   Turn your mobile device into a SAM node, exposing sensors and telemetry securely to the mesh, and integrating with native OS assistants.
