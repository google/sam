---
title: "Gemini Buddy"
linkTitle: "Gemini Buddy"
weight: 20
---

Hold a real multi-turn conversation with a *second* LLM exposed as an ordinary
mesh service — where your agent never resends the conversation, because the
service remembers its own side.

Source: [`development/examples/gemini-buddy-mcp/`](https://github.com/google/sam/tree/main/development/examples/gemini-buddy-mcp).

## The idea

Sometimes you want your agent to *talk to another model* — a second opinion, a
peer to argue a design with, a specialist that builds up its own context over
many turns. The naive way is to carry both conversations in the orchestrator:
your agent would have to store the other model's transcript and replay all of it
on every turn.

This use case shows you don't have to. A **buddy** is a plain MCP service backed
by the Gemini CLI that **owns its own conversation**. Your agent sends one
message per turn and gets one reply; the buddy keeps the running transcript
server-side, keyed by a `session_id`. It's built from nothing but an ordinary
`sam-node` MCP service — the conversational evolution of the one-shot
[`code-reviewer`](https://github.com/google/sam/tree/main/development/examples/code-reviewer-mcp)
example.

## Two conversations, two places

The confusion this example clears up: talking to another LLM does *not* mean
maintaining two conversations from your side.

- **Your conversation** (you ↔ your agent) lives in your agent's context.
- **The buddy's conversation** lives inside the buddy service process.

When your agent calls the buddy's `chat` tool it sends **only the next message**,
never the history. The buddy appends it to that session's transcript, replays the
whole transcript *locally* to a one-shot `gemini -p` call, stores the reply, and
returns just that reply. The reply naturally becomes part of your agent's context
like any other tool result — so neither side ever double-maintains the other's
transcript.

That makes the buddy service the **conversation owner** and the model a
swappable, stateless backend: the same service works for any CLI (`gemini`,
`claude`, `codex`, …) by changing one `spawn` line.

## The pieces

- **`gemini-buddy` service** — a normal MCP service exposing two tools:
  - `chat` — takes `{ message, session_id? }` (session defaults to `"default"`),
    appends the message to that session's in-memory transcript, runs one
    `gemini -p` turn with the transcript on stdin, and returns the buddy's reply.
  - `reset` — takes `{ session_id? }` and wipes that session so the next `chat`
    starts fresh.
- **Orchestrator** — any mesh MCP client (an agent harness or a custom program).
  It discovers the buddy with `find_remote_tools(gemini-buddy)` and drives it with
  `call_remote_tool(peer, chat, …)` — one message at a time.

## What you can do with it

- **Second opinion / peer** — bounce a design or a tricky bug off a different
  model across several turns without babysitting its context.
- **Specialist that accumulates context** — let the buddy build up domain
  knowledge over many messages (walk it through a subsystem, then keep asking)
  that your own agent never has to reload.
- **A reusable pattern** — swap the Gemini CLI for any other model CLI; the
  service structure (own the transcript, shell a stateless one-shot per turn) is
  identical. `reset` gives you clean, isolated sessions on demand.

## Try it on kind

The repository ships a [kind](https://kind.sigs.k8s.io/)-based local mesh that
brings the buddy up with one command.

### 1. Set an LLM key for the buddy image

The buddy shells out to the Gemini CLI, so set your API key on the API-key `ENV`
line in `development/examples/gemini-buddy-mcp/Dockerfile` before building (a free
Google AI Studio key is fine for the demo).

### 2. Mesh layout

Host the buddy on one node in `development/kind/mesh-config.yaml`:

```yaml
node-a:                    # bare node (orchestrator entry)
node-b: gemini-buddy-mcp   # the buddy
node-c:
node-d:
node-e:
```

### 3. Bring the mesh up and start a local orchestrator node

```bash
make build            # builds ./bin/sam-node (once)
make kind-up          # hub + buddy (node-b)
make kind-local-node  # local sam-node enrolled in the mesh — LEAVE RUNNING
```

`kind-local-node` runs in the foreground in its own shell and exposes the mesh
MCP tools at **`http://127.0.0.1:9099/mcp`** (bearer token `devtoken`) — no
`kubectl port-forward` needed. This local node is your orchestrator's entry point
into the mesh.

### 4. Point your harness at the local node

Add the local node as an MCP server in whatever harness you drive the mesh from.
The specifics differ per harness (some use a JSON/TOML config file, others a UI),
but the settings are always the same:

- **Transport:** HTTP (Streamable HTTP / `http`)
- **URL:** `http://127.0.0.1:9099/mcp`
- **Header:** `Authorization: Bearer devtoken`

For example, harnesses that use the common `mcpServers` JSON config (Claude Code,
Cursor, and others) would add:

```json
{
  "mcpServers": {
    "sam-mesh": {
      "type": "http",
      "url": "http://127.0.0.1:9099/mcp",
      "headers": { "Authorization": "Bearer devtoken" }
    }
  }
}
```

Consult your harness's MCP documentation for its exact config format. Once
connected, the mesh exposes `find_remote_tools` and `call_remote_tool` as tools
your agent (or program) can call.

### 5. Have a conversation

Just tell your agent what you want — the mesh tool descriptions and the buddy's
own instructions steer it to discover the service and route each turn, so you
don't have to name any tools. A natural first prompt:

> Find the `gemini-buddy` service in the mesh, then introduce yourself and tell it
> I'm planning a trip to Kyoto in spring and that I'm slightly obsessed with ramen.

Then, in a *separate* message, prove the buddy remembers without you resending
anything:

> Ask the buddy where I'm headed and what food I'm into. Don't remind it — just ask.

The buddy answers correctly even though your agent never re-sent the first turn:
the transcript lives in the service, not in your context. Finally, wipe it:

> Reset the conversation with the buddy, then ask it where I'm going again.

After the reset it no longer knows — the service dropped that session's
transcript.

Once you've got the hang of it, hand the whole loop to your agent and have fun
watching two models converse:

> Find the `gemini-buddy` service on the SAM mesh, reset its session, then have a
> 10-turn conversation with it — one question per turn, each building on its last
> answer, and show me every question-and-answer pair as you go.

## Configuration

| var | default | used by |
|-----|---------|---------|
| `GEMINI_API_KEY` | *(placeholder — set in the Dockerfile)* | buddy |
| `GEMINI_CLI_TRUST_WORKSPACE` | `true` | buddy |

The listen port (`7780`) and model (`gemini-3.1-flash-lite`) are constants at the
top of `buddy_server.mjs`; change them there if needed.
