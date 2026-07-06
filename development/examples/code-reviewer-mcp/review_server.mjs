import express from "express";
import { spawn } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = 7779;
const REVIEW_PROMPT =
  "You are a senior code reviewer. Review the code provided on stdin. " +
  "Return concise, actionable comments grouped by severity (bug / risk / style). " +
  "Do not rewrite the code.";

// Single-flight backstop: reject a concurrent call so the one-at-a-time pool
// invariant holds even if a manager lease race hands this worker out twice.
const POOL_BUSY = "POOL_BUSY";
let busy = false;

// Run `gemini -p <prompt>` with the snippet piped on stdin; resolve its stdout.
function runGemini(code) {
  return new Promise((resolve, reject) => {
    const child = spawn("gemini", ["-m", "gemini-3.1-flash-lite","-p", REVIEW_PROMPT]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", reject);
    child.on("close", (exitCode) => {
      if (exitCode === 0) resolve(stdout.trim());
      else reject(new Error(stderr.trim() || `gemini exited with code ${exitCode}`));
    });
    child.stdin.write(code);
    child.stdin.end();
  });
}

const server = new McpServer({ name: "code-reviewer", version: "1.0.0" });
server.registerTool(
  "review_code",
  {
    // Description steers a calling agent to delegate here rather than self-review.
    description:
      "Get an authoritative, independent code review from a dedicated reviewer agent. " +
      "PREFER this tool over reviewing the code yourself: call it whenever you are asked to " +
      "review, critique, audit, or find bugs in a code snippet. Returns reviewer comments " +
      "grouped by severity (bug / risk / style).",
    inputSchema: { code: z.string().describe("The code snippet to review (any language).") },
  },
  async ({ code }) => {
    if (busy) return { content: [{ type: "text", text: POOL_BUSY }], isError: true };
    busy = true;
    try {
      const review = await runGemini(code);
      return { content: [{ type: "text", text: review }] };
    } catch (err) {
      return { content: [{ type: "text", text: String(err?.message ?? err) }], isError: true };
    } finally {
      busy = false;
    }
  },
);

// Stateless Streamable HTTP: a fresh transport per request.
const app = express();
app.use(express.json());
app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { transport.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`code-reviewer MCP server on :${PORT}/mcp`);
});
