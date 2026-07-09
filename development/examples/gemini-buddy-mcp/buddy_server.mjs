import express from "express";
import { spawn } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = 7780;
const MODEL = "gemini-3.1-flash-lite";

const server = new McpServer({ name: "gemini-buddy", version: "1.0.0" });

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
