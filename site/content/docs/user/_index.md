---
title: "User and Operator Guides"
linkTitle: "User Guides"
weight: 3
---

Welcome to the User & Operator Guides. This section provides detailed documentation on how to configure, run, and manage Sovereign Agent Mesh (SAM) clusters, hubs, and node configurations.

### In This Section

1. **[Hub Configuration](hub-configuration.md)**
   Learn how to configure the OIDC identity bridge, set up cryptographic private keys, enforce TLS/mTLS, and write custom security role policy mappings in `policies.yaml`.

2. **[Agent Usage & Connectivity](agent-usage.md)**
   Understand how nodes connect to the mesh via OIDC login, secure credentials, run local Model Context Protocol (MCP) servers, and expose secure remote tool access to agents (like Google Gemini and Claude).

3. **[Production Kubernetes Deployment](kubernetes-deployment.md)**
   Deploy a production-grade mesh cluster in Kubernetes, including Dex OIDC setups, StatefulSet P2P hubs, DNS A-record synchronizers, and Workload Identity ServiceAccount token projections.
