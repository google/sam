---
title: "Use Cases"
linkTitle: "Use Cases"
weight: 5
---

Worked examples of what you can build **on top of the mesh** — patterns that
combine ordinary `sam-node` MCP services (discovery, remote tool calls, leasing)
into something larger, with no changes to the node itself.

Each use case is harness-agnostic: the orchestrator is any MCP client — an agent
harness (Claude Code, Codex, Antigravity, …) or a custom program — talking to the
mesh MCP tools exposed by a local node.

The runnable source for every example lives under
[`development/examples/`](https://github.com/google/sam/tree/main/development/examples)
in the repository; each page here links to its example directory.
