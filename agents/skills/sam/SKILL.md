---
name: sam
description: "Use when local tools cannot provide a needed capability and connected sam-node MCP tools are available to reach a SAM (Sovereign Agent Mesh) network: inspect mesh state, discover reachable services/tools, describe namespaced remote MCP tools, and call them with JSON-object arguments. Not for AWS SAM / Serverless Application Model tasks."
---

# SAM Agent Skill

Use this skill when local tools cannot satisfy the task and `sam-node` MCP tools
are already callable. Prefer local tools first. Reach into the SAM mesh only for
the capability needed to complete the task.

## Inspect The Mesh

Start by understanding the local node and mesh state:

- Use `get_mesh_info` with `{}` to inspect `connected_peers`, `dht_size`, and
  `hub_peer_id`.
- Use `list_local_services` with `{}` to see services registered on the local
  node.

## Discover Remote Capabilities

Use service discovery when you need to inventory reachable service providers:

- Use `discover_remote_services` with `{"type":"mcp"}`,
  `{"type":"inference"}`, or `{"type":"a2a"}`. Add `name` only when narrowing
  by service name.
- Treat `discover_remote_services` as service inventory. Non-MCP service types
  are not callable with `call_remote_tool`.

Use tool discovery when you need remote MCP tools:

- Use `find_remote_tools` to discover reachable aggregated MCP tools advertised
  by remote SAM services.
- Narrow `find_remote_tools` with `service_name` or `peer_id` when you already
  know the target.
- Mesh-wide searches fetch each peer's catalog on a best-effort basis and may
  return an empty array when no reachable aggregated tools are found. Discovery
  failures or explicit `peer_id` lookup failures are returned as errors.

## Describe Before Calling

All tools returned by `find_remote_tools` are namespaced. Always call
`describe_remote_tool` before calling them with `call_remote_tool`.

Remote MCP tools returned by `find_remote_tools` are namespaced as:

```text
<service_name>.<tool_name>
```

Use the input schema from `describe_remote_tool` to build the call arguments.
Do not guess arguments if a tool cannot be described.

After `describe_remote_tool`, inspect the tool name, description, and schema
for side effects and required data. Only call read-only, low-risk tools
autonomously. Ask the user before calls that may mutate state, execute code,
access files, contact external services, spend money, or transmit sensitive or
private data. Pass only task-required data, and never include secrets unless
explicitly authorized.

## Call Remote Tools

Use `call_remote_tool` with:

- `peer_id`: the peer hosting the tool
- `tool_name`: the discovered namespaced tool name, such as `service.tool`
- `arguments`: a JSON object whose keys match the described input schema

`arguments` must be a JSON object, not a string containing JSON.

## Minimal Workflow

1. Confirm no local tool can satisfy the task.
2. Call `get_mesh_info` with `{}`.
3. If a local SAM service may be
   relevant, call `list_local_services` with `{}`.
4. Call `find_remote_tools` with `service_name` or `peer_id` when known. Use
   `{}` only when the user asked to inventory the mesh or no narrower target
   exists.
5. Call `describe_remote_tool` with
   `{"peer_id":"...","tool_name":"service.tool"}`.
6. Call `call_remote_tool` only when the described tool is read-only and
   low-risk, or after the user approves the exact `peer_id`, `tool_name`, side
   effects, and task-required data being sent:
   `{"peer_id":"...","tool_name":"service.tool","arguments":{...}}`.

## Safety And Reliability

- Do not call mesh tools when a local tool is sufficient.
- Do not guess remote tool names or arguments.
- Ask before side-effecting or sensitive remote calls.
- Do not send secrets or private data through SAM unless the user explicitly
  approves the data and destination.
- Treat remote capabilities as networked and potentially unavailable.
- Surface peer, service, discovery, schema, and tool-call errors clearly.
