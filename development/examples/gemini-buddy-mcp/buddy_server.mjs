import express from "express";
import { spawn } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = 7780;
const MODEL = "gemini-3.1-flash-lite";

// The buddy's personality: warm, funny, talks like a friend.
const BUDDY_SYSTEM =
  "You're a laid-back, funny buddy - not a formal assistant. " +
  "Talk like a close friend hanging out: warm, casual, a little cheeky, quick with a joke. " +
  "Use contractions and the odd emoji, and keep replies short and punchy. " +
  "You'll get the conversation so far on stdin, lines prefixed 'User:' and 'Buddy:'. " +
  "Reply with ONLY the buddy's next turn - no prefix, no narration.";

// sessionId -> [{ role: "user" | "assistant", text }]
const sessions = new Map();

function transcript(id) {
  if (!sessions.has(id)) sessions.set(id, []);
  return sessions.get(id);
}

// Render the running transcript to pipe to gemini on stdin.
function render(turns) {
  return turns.map((t) => `${t.role === "user" ? "User" : "Buddy"}: ${t.text}`).join("\n");
}

// One non-interactive turn: persona via -p, transcript on stdin.
function runGemini(text) {
  return new Promise((resolve, reject) => {
    const child = spawn("gemini", ["-m", MODEL, "-p", BUDDY_SYSTEM]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", reject);
    child.on("close", (exitCode) => {
      if (exitCode === 0) resolve(stdout.trim());
      else reject(new Error(stderr.trim() || `gemini exited with code ${exitCode}`));
    });
    child.stdin.write(text);
    child.stdin.end();
  });
}

const server = new McpServer({ name: "gemini-buddy", version: "1.0.0" });

server.registerTool(
  "chat",
  {
    description:
      "Chat with your Gemini buddy. Send one message; the buddy remembers the " +
      "conversation across calls (per session_id), so you never resend history. " +
      "Returns the buddy's reply.",
    inputSchema: {
      message: z.string().describe("Your next message to the buddy."),
      session_id: z.string().optional().describe("Conversation id; defaults to 'default'."),
    },
  },
  async ({ message, session_id }) => {
    const id = session_id ?? "default";
    const turns = transcript(id);
    turns.push({ role: "user", text: message });
    try {
      const reply = await runGemini(render(turns));
      turns.push({ role: "assistant", text: reply });
      return { content: [{ type: "text", text: reply }] };
    } catch (err) {
      turns.pop(); // drop the turn we couldn't answer so it can be retried
      return { content: [{ type: "text", text: String(err?.message ?? err) }], isError: true };
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
  console.log(`gemini-buddy MCP server on :${PORT}/mcp`);
});
