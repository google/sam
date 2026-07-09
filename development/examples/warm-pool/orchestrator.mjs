// Headless warm-pool orchestrator (alternative to driving it from Claude Code).
// For each file: acquire a free worker from the pool-manager, review, release.
// All tasks run concurrently; the manager's blocking acquire + leasing serialize
// dispatch to the pool size, so no local queue is needed.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const NODE_URL = process.env.SAM_NODE_URL ?? "http://127.0.0.1:9099/mcp";
const API_TOKEN = process.env.SAM_API_TOKEN ?? "devtoken";
const ACQUIRE_TIMEOUT = Number(process.env.SAM_ACQUIRE_TIMEOUT ?? 60);

function collectFiles(paths) {
  const out = [];
  for (const p of paths) {
    if (statSync(p).isDirectory()) {
      for (const f of readdirSync(p)) {
        const fp = join(p, f);
        if (statSync(fp).isFile()) out.push(fp);
      }
    } else {
      out.push(p);
    }
  }
  return out;
}

const short = (peer) => peer.slice(-8);

async function main() {
  const files = collectFiles(process.argv.slice(2));
  if (!files.length) {
    console.error("usage: node orchestrator.mjs <file|dir> ...");
    process.exit(1);
  }
  const tasks = files.map((f) => ({ name: f, code: readFileSync(f, "utf8") }));
  console.log(`queued ${tasks.length} review task(s)`);

  const client = new Client({ name: "warm-pool-orchestrator", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(NODE_URL), {
    requestInit: { headers: { Authorization: `Bearer ${API_TOKEN}` } },
  });
  await client.connect(transport);

  const call = async (peer, tool, args) => {
    const res = await client.callTool({ name: "call_remote_tool", arguments: { peer_id: peer, tool_name: tool, arguments: args } });
    return res?.content?.[0]?.text ?? "";
  };

  // Locate the pool-manager peer (tool names are full URIs).
  const found = JSON.parse((await client.callTool({ name: "find_remote_tools", arguments: {} })).content[0].text);
  const manager = found.find((r) => r.tool_name === "mcp://pool-manager/acquire_worker")?.peer_id;
  if (!manager) { console.error("no pool-manager found in the mesh"); process.exit(1); }
  console.log(`pool-manager at ${short(manager)}`);

  const t0 = Date.now();
  const elapsed = () => ((Date.now() - t0) / 1000).toFixed(1);

  const process1 = async (task) => {
    for (;;) {
      const acq = JSON.parse(await call(manager, "mcp://pool-manager/acquire_worker", { timeout_secs: ACQUIRE_TIMEOUT }));
      if (!acq.peer_id) { console.error(`[+${elapsed()}s] no worker for ${task.name}`); return null; }
      console.log(`[+${elapsed()}s] -> ${short(acq.peer_id)}  ${task.name}`);
      let review;
      try {
        review = await call(acq.peer_id, acq.tool, { code: task.code, token: acq.token });
      } finally {
        await call(manager, "mcp://pool-manager/release_worker", { peer_id: acq.peer_id, lease_id: acq.lease_id });
      }
      // Worker single-flight backstop tripped; the lease race is rare, so retry.
      if (review.trim() === "POOL_BUSY") { console.log(`[+${elapsed()}s] ~~ ${short(acq.peer_id)} busy, retrying ${task.name}`); continue; }
      console.log(`[+${elapsed()}s] <- ${short(acq.peer_id)}  ${task.name}  (${review.length} chars)`);
      return { ...task, peer: acq.peer_id, review };
    }
  };

  const results = (await Promise.all(tasks.map(process1))).filter(Boolean);

  console.log(`\n=== done in ${elapsed()}s: ${results.length} review(s) across ${new Set(results.map((r) => r.peer)).size} worker(s) ===`);
  for (const r of results) {
    console.log(`\n----- ${r.name}  (reviewed by ${short(r.peer)}) -----\n${r.review}`);
  }
  await client.close();
}

main().catch((e) => { console.error(e); process.exit(1); });
