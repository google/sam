# Code-reviewer pool — warm agent pool demo

Fan a batch of files out to a **pool of identical reviewer workers**. A
**manager** mesh service tracks which workers are free and leases them out;
Claude Code (the orchestrator) acquires a worker, reviews a file, and releases
it. Reviews run in parallel across the pool.

Design: `docs/superpowers/specs/2026-06-28-warm-agent-pool-design.md`.

## Architecture (no gossip, no node changes — just services)

- **Workers:** plain `code-reviewer` mcp services (node-b/c/d), under `reviewer/`.
- **manager** (node-e, under `manager/`): a normal mcp service exposing
  `acquire_worker` / `release_worker` / `list_workers`. It is also a northbound
  MCP client of its own node: every few seconds it calls
  `find_remote_tools(service_name="code-reviewer")` to learn the worker peers
  (DHT), and it tracks free/busy with **leases**.
- **Orchestrator:** `acquire_worker` → `call_remote_tool(peer, review_code)` →
  `release_worker`. Leasing hands each concurrent acquire a different worker, so
  parallel dispatch never collides.

Why no gossip: the manager gets *who exists* from DHT discovery and *who's busy*
from its own leases — the two things a readiness broadcast would have provided.
The tradeoff: leasing is authoritative only while the manager is the sole
dispatcher (fine for a single-manager pool).

### Concurrency hardening

- **No double-lease:** the manager is single-threaded and `leaseFree()` is
  synchronous, so two concurrent `acquire_worker` calls can never get the same
  worker.
- **Grace eviction:** discovery never drops a *leased* worker on a transient
  miss, and only drops a free one after `SAM_GRACE_MISSES` consecutive misses —
  so a slow (busy) worker isn't freed early.
- **Fencing tokens:** `acquire_worker` returns a `lease_id`; `release_worker`
  clears the lease only if the id still matches, so a late release from an
  expired lease can't free a newer holder's worker.
- **Worker single-flight backstop:** `review_code` returns `POOL_BUSY` if already
  running; the caller retries. This keeps the one-at-a-time invariant even if a
  lease race ever slips through.

## Run it

1. **Set a Gemini key** for the reviewer image (free AI Studio key is fine):
   ```
   git update-index --skip-worktree development/examples/code-reviewer-pool/reviewer/Dockerfile
   # edit ENV GEMINI_API_KEY=<API_KEY> in that Dockerfile
   ```

2. Mesh layout ships in `development/kind/mesh-config.yaml`:
   ```yaml
   node-a:                                 # in-cluster bare node
   node-b: code-reviewer-pool/reviewer     # worker
   node-c: code-reviewer-pool/reviewer     # worker
   node-d: code-reviewer-pool/reviewer     # worker
   node-e: code-reviewer-pool/manager      # manager
   ```

3. Bring the mesh up and start a **local caller node** — this is the orchestrator
   entry point:
   ```
   make build          # builds ./bin/sam-node (once)
   make kind-up        # hub + reviewer pool (node-b/c/d) + manager (node-e)
   make kind-local-node   # local sam-node enrolled in the mesh — LEAVE RUNNING
   ```
   `kind-local-node` runs in the foreground (own shell). It exposes the mesh MCP
   tools at **`http://127.0.0.1:9099/mcp`** (token `devtoken`) — no
   `kubectl port-forward` needed.

### Drive it from Claude Code

Register the local node as an MCP server (`.mcp.json` in the project root):
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
Reconnect Claude Code, then prompt:
> Using the sam-mesh tools: find the pool-manager, then for each file in
> `development/examples/code-reviewer-pool/samples/` acquire a worker, call its
> `review_code` with the file contents, and release it (pass the lease_id back
> to release_worker). Run them in parallel.

Claude fires parallel `acquire_worker` → `call_remote_tool` → `release_worker`
chains; you watch the reviews come back concurrently.

## Elasticity beat (add a worker mid-job)

Scale a reviewer down, start a larger job, then scale it back up — the manager
picks the new worker up on its next discovery pass and starts leasing it:
```
kubectl --context kind-sam-kind -n sam-kind scale deploy/node-d --replicas=0
# start a big job, then:
kubectl --context kind-sam-kind -n sam-kind scale deploy/node-d --replicas=1
```

## Config (env vars)

| var | default | used by |
|-----|---------|---------|
| `SAM_NODE_URL` | `http://127.0.0.1:8080/mcp` | manager |
| `SAM_API_TOKEN` | `devtoken` | manager |
| `SAM_POOL_SERVICE` | `code-reviewer` | manager |
| `SAM_DISCOVERY_MS` | `3000` | manager |
| `SAM_LEASE_MS` | `60000` | manager |
| `SAM_GRACE_MISSES` | `2` | manager |
| `SAM_POOL_SECRET` | `sam-dev-pool-secret` (enforcement always on) | manager + reviewer |

## Lease enforcement

Every reviewer requires a valid lease: the manager signs a token on
`acquire_worker`, and the reviewer verifies it offline and returns `NO_LEASE`
for any `review_code` call without a valid, unexpired one. Both sides share a
hardcoded dev secret (`sam-dev-pool-secret`) so it works out of the box; override
it by setting the same `SAM_POOL_SECRET` on the manager and every reviewer. A
mismatch (or setting it on only one side) fails closed: every call returns
`NO_LEASE`.
