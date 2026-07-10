---
title: "Warm Agent Pool"
linkTitle: "Warm Agent Pool"
weight: 10
---

Fan a batch of work across a pool of identical, already-running worker agents —
built entirely from ordinary mesh MCP services, no gossip and no node changes.

Source: [`development/examples/code-reviewer-pool/`](https://github.com/google/sam/tree/main/development/examples/code-reviewer-pool).

## The idea

Some agent tools are expensive to stand up but cheap to reuse — a reviewer that
shells out to an LLM, a sandbox that boots a runtime, a service holding a warm
model in memory. You don't want to spawn one per request, and you don't want a
single instance serialising all your work. What you want is a **pool of
identical, already-running workers** and something that hands them out one job at
a time.

This use case builds exactly that on the mesh, using **nothing but ordinary MCP
services**. The worked example is a *code reviewer*: several identical reviewer
workers, a manager that leases them, and an orchestrator that fans a batch of
files across the pool in parallel.

## The pieces

- **Workers** — plain `code-reviewer` MCP services. Each exposes a single
  `review_code` tool that pipes the snippet to an LLM and returns comments
  grouped by severity. They're stateless and interchangeable; the pool's job is
  to keep them busy.
- **Manager** — a normal MCP service exposing `acquire_worker` /
  `release_worker` / `list_workers`. It's also a *northbound MCP client of its
  own node*: every few seconds it calls `find_remote_tools(code-reviewer)` to
  learn which worker peers exist (via the DHT), and it tracks which of them are
  free or busy using **leases**.
- **Orchestrator** — any mesh MCP client (an agent harness or a custom program).
  The loop per file is: `acquire_worker` → `call_remote_tool(peer, review_code)`
  → `release_worker`. Run those chains concurrently and each acquire hands back a
  *different* free worker, so parallel dispatch never collides.

## Why there's no readiness broadcast

A classic worker pool needs to know two things: *who exists* and *who's busy*.
The manager gets the first from **DHT discovery** and the second from **its own
leases** — the exact two facts a gossip/readiness broadcast would otherwise
provide. So the whole thing runs on discovery + leasing, no pub/sub. The
tradeoff: leasing is authoritative only while the manager is the *sole*
dispatcher — perfect for a single-manager pool, and the point at which you'd
reach for real coordination if you needed multiple managers.

## What makes it correct under concurrency

The interesting part is that "hand out a warm worker, one job at a time" stays
true even when acquires race and workers come and go:

- **No double-lease** — the manager is single-threaded and `leaseFree()` is fully
  synchronous (no `await` between picking a worker and marking it busy), so two
  concurrent `acquire_worker` calls can never be handed the same peer.
- **Grace eviction** — discovery never drops a *leased* worker on a transient
  miss, and only drops a *free* one after `SAM_GRACE_MISSES` consecutive misses.
  A slow, busy worker won't get evicted and re-handed-out mid-review.
- **Fencing tokens** — `acquire_worker` returns a `lease_id`; `release_worker`
  only clears the lease if that id still matches, so a late release from an
  expired lease can't free a *newer* holder's worker.
- **Single-flight backstop** — even if a lease race ever slipped through, the
  worker itself returns `POOL_BUSY` for a second concurrent `review_code`, so the
  one-at-a-time invariant holds at the source.

## Lease enforcement (workers trust the manager, not the caller)

Workers don't hand out reviews to anyone who can reach them. On `acquire_worker`
the manager **mints a short-lived HMAC token** bound to that worker and lease
expiry; the orchestrator forwards it in the `review_code` arguments, and the
worker **verifies it offline** (shared secret, no call back to the manager). Any
`review_code` without a valid, unexpired token gets `NO_LEASE`. Both sides
default to a hardcoded dev secret (`sam-dev-pool-secret`) so it enforces out of
the box; set a matching `SAM_POOL_SECRET` on the manager and every worker to
override it. Mismatched or one-sided secrets **fail closed** — every call returns
`NO_LEASE`.

## What you can do with it

- **Parallel batch work** — fan a directory of files (or tasks) across N warm
  workers and collect results as they land, bounded by pool size rather than
  serialised.
- **Elastic capacity** — scale a worker deployment up or down mid-job; the
  manager picks a new worker up on its next discovery pass and starts leasing it,
  and drains one that disappears without corrupting in-flight leases.
- **A reusable pattern** — swap `code-reviewer` for any expensive-to-warm tool
  (test runner, sandbox, embedder, browser). The manager is generic; it pools
  whatever `SAM_POOL_SERVICE` names.

## Try it on kind

The repository ships a [kind](https://kind.sigs.k8s.io/)-based local mesh that
brings up the whole pool with one command.

### 1. Set an LLM key for the reviewer image

The reviewer workers shell out to an LLM, so set your API key on the API-key
`ENV` line in `development/examples/code-reviewer-pool/reviewer/Dockerfile`
before building (a free key is fine for the demo).

### 2. Mesh layout

The layout ships in `development/kind/mesh-config.yaml`:

```yaml
node-a:                                 # bare node (orchestrator entry)
node-b: code-reviewer-pool/reviewer     # worker
node-c: code-reviewer-pool/reviewer     # worker
node-d: code-reviewer-pool/reviewer     # worker
node-e: code-reviewer-pool/manager      # manager
```

### 3. Bring the mesh up and start a local orchestrator node

```bash
make build            # builds ./bin/sam-node (once)
make kind-up          # hub + reviewer pool (node-b/c/d) + manager (node-e)
make kind-local-node  # local sam-node enrolled in the mesh — LEAVE RUNNING
```

`kind-local-node` runs in the foreground in its own shell and exposes the mesh
MCP tools at **`http://127.0.0.1:9099/mcp`** (bearer token `devtoken`) — no
`kubectl port-forward` needed. This local node is your orchestrator's entry
point into the mesh.

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
connected, the mesh exposes `acquire_worker`, `release_worker`, `list_workers`,
`find_remote_tools`, and `call_remote_tool` as tools your agent (or program) can
call.

### 5. Drive the pool

Have your orchestrator run, per file, in parallel:

1. `acquire_worker` → returns `{peer_id, tool, lease_id, token}`.
2. `call_remote_tool(peer_id, review_code, {code, token})` — forward the `token`
   in the tool arguments (the pool requires it).
3. `release_worker(peer_id, lease_id)` — pass the `lease_id` back so a stale
   release can't free a newer holder.

A natural prompt for an agent harness:

> Using the `sam-mesh` tools: for each file in
> `development/examples/code-reviewer-pool/samples/`, acquire a worker, call its
> `review_code` with the file contents (forwarding the token), and release it
> (pass the `lease_id` back). Run them in parallel.

You'll watch the reviews come back concurrently, bounded by the number of workers
in the pool.

### 6. Elasticity beat (add a worker mid-job)

Scale a reviewer down, start a larger job, then scale it back up — the manager
picks the new worker up on its next discovery pass and starts leasing it:

```bash
kubectl --context kind-sam-kind -n sam-kind scale deploy/node-d --replicas=0
# start a big job, then:
kubectl --context kind-sam-kind -n sam-kind scale deploy/node-d --replicas=1
```

## Configuration

| var | default | used by |
|-----|---------|---------|
| `SAM_NODE_URL` | `http://127.0.0.1:8080/mcp` | manager |
| `SAM_API_TOKEN` | `devtoken` | manager |
| `SAM_POOL_SERVICE` | `code-reviewer` | manager |
| `SAM_DISCOVERY_MS` | `3000` | manager |
| `SAM_LEASE_MS` | `60000` | manager |
| `SAM_GRACE_MISSES` | `2` | manager |
| `SAM_POOL_SECRET` | `sam-dev-pool-secret` (enforcement always on) | manager + reviewer |
