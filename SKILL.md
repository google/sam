---
name: sam
description: "Use this skill only for SAM (Sovereign Agent Mesh) tasks through a local sam-node MCP server: inspecting mesh state, discovering reachable services/tools, describing namespaced remote MCP tools, and calling them with JSON-object arguments. Do not use for AWS SAM or Serverless Application Model tasks."
---

# SAM Agent Skill

Use SAM when a local `sam-node` is available and the task needs capabilities
hosted by peers in a SAM mesh. Prefer local tools first. Reach into the mesh
only when the needed capability is not available locally.

## Connect To The Local Node

Connect to the local `sam-node` MCP SSE endpoint:

```text
http://127.0.0.1:8080/mcp/events
```

If the user or local configuration explicitly provides a trusted non-loopback
endpoint, ask the user to confirm the exact endpoint and trust boundary before
connecting. Prefer loopback endpoints (`127.0.0.1`, `localhost`, or `::1`), and
do not send secrets or sensitive data to non-loopback endpoints unless the user
explicitly approves the destination and data. Do not probe, guess, or scan
non-local bind addresses. The server also registers `/mcp/message` as the
paired MCP message endpoint; MCP clients and SDKs normally handle this after
connecting through `/mcp/events`.

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

1. Call `get_mesh_info` with `{}`.
2. Confirm no local tool can satisfy the task. If a local SAM service may be
   relevant, call `list_local_services` with `{}`.
3. Call `find_remote_tools` with `service_name` or `peer_id` when known. Use
   `{}` only when the user asked to inventory the mesh or no narrower target
   exists.
4. Call `describe_remote_tool` with
   `{"peer_id":"...","tool_name":"service.tool"}`.
5. Call `call_remote_tool` only when the described tool is read-only and
   low-risk, or after the user approves the exact `peer_id`, `tool_name`, side
   effects, and task-required data being sent:
   `{"peer_id":"...","tool_name":"service.tool","arguments":{...}}`.

## Safety And Reliability

- Do not call mesh tools when a local tool is sufficient.
- Do not guess remote tool names or arguments.
- Ask before side-effecting or sensitive remote calls.
- Treat remote capabilities as networked and potentially unavailable.
- Surface peer, service, discovery, schema, and tool-call errors clearly.
