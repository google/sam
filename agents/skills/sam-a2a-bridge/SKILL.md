---
name: sam-a2a-bridge
description: "Use when the task should be delegated to a remote A2A agent on the SAM (Sovereign Agent Mesh) network: send it work with send_agent_task, poll results with get_agent_task, hold multi-turn conversations, and enforce data-sovereignty labels on every call. Also use to set up the sam-a2a-bridge MCP server when those two tools are not callable yet."
---

# SAM A2A Bridge Skill

Use this skill to delegate work to A2A agents hosted by SAM mesh peers. The
bridge exposes exactly two tools; everything else (auth, routing, the labels
gate) happens inside the local `sam-node`.

Pick the path that matches the need:

- `send_agent_task` / `get_agent_task` are not callable yet:
  [Set Up The Bridge](#set-up-the-bridge).
- The task needs a remote agent to do something:
  [Send A Task](#send-a-task).
- A previous send returned a non-terminal state:
  [Poll A Task](#poll-a-task).
- The conversation with the agent continues:
  [Multi-Turn](#multi-turn).
- A call failed: [Interpret Errors](#interpret-errors).

## Set Up The Bridge

The bridge is a stdio MCP server that talks to the local `sam-node` sidecar.
Propose each shell command and let the user approve it before running anything.

1. A running, enrolled `sam-node` is required first. If its sidecar does not
   answer on `http://localhost:8080`, use the `sam-mesh` skill's bootstrap
   path before continuing.
2. Build the bridge (own Go module, Go >= 1.25):
   `cd <sam-repo>/cmd/sam-a2a-bridge && go build -o ~/bin/sam-a2a-bridge .`
3. Register it with the harness, passing the sidecar URL and its API token:
   `claude mcp add sam-a2a-bridge -- ~/bin/sam-a2a-bridge -url http://localhost:8080 -token <sidecar-token>`
4. Restart the harness session; the two tools appear.

## Send A Task

`send_agent_task(peer, service, message, required_labels?, context_id?, task_id?)`

- `peer` is the provider node's peer ID; `service` is the a2a service name it
  registered. If unknown, discover them with the `sam-node` MCP tool
  `discover_remote_services` with `type: a2a`, or ask the user.
- `message` is plain text. The call returns immediately with
  `{"task_id","context_id","state","text"}` — it never blocks on the agent.
- **Sovereignty**: when the task involves data that must stay in a region or
  jurisdiction, set `required_labels` (comma-separated `key=value`, e.g.
  `region=eu-west-1`). The local node then refuses fail-closed before any data
  leaves it unless the peer's control-plane-attested labels match. Never drop
  or weaken `required_labels` to make a refused call succeed without the
  user's explicit approval — the refusal is the feature.

## Poll A Task

If `state` is not terminal (`completed`, `failed`, `canceled`, `rejected`),
poll with `get_agent_task(peer, service, task_id)` until it is. Space polls a
few seconds apart; agent tasks can be slow. `text` carries the agent's status
message while running and its answer or artifacts when completed.

## Multi-Turn

- Follow-up question in the same conversation: pass the returned `context_id`
  on the next `send_agent_task`. Without it every message is a cold start.
- The task is in state `input-required` (the agent asked something): answer by
  passing BOTH `task_id` and `context_id` — that routes the reply into the
  waiting task so it can finish. Terminal tasks cannot receive messages.

## Interpret Errors

- `403: Required labels not attested by provider` — the sovereignty gate
  refused before egress. Expected for non-matching regions; report it to the
  user, do not retry with weaker labels on your own.
- `400: Invalid X-Sam-Required-Labels header ...` — malformed labels; fix the
  `key=value,key=value` syntax.
- `404` / `Service not found` — the peer has no a2a service by that name;
  re-discover or check the name with the user.
- Connection refused / timeout — the local sidecar URL or token is wrong, or
  the node is down; go to [Set Up The Bridge](#set-up-the-bridge).
- Interop note: the remote agent must run a2a-go v2.x; older A2A stacks speak
  a different JSON-RPC dialect and will not answer.
