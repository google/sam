# Hybrid Intelligence Audit

## Problem

You have sensitive local data (contracts, internal code, regulated documents) that cannot be uploaded to cloud LLMs, but you still need high-quality reasoning against public and constantly changing sources.

The target workflow is:

1. Read and sanitize private documents locally.
2. Pull current public policy/specification data from the web.
3. Synthesize one final audit report.

## Architecture: Hybrid Research Assistant

- Private Core: local `llama-server` processes sensitive files.
- Public Edge: Gemini 1.5 Pro (via LangChain) handles broad reasoning and web context.
- Connective Tissue: SAM provides secure peer-to-peer discovery and A2A transport so private data paths stay under your control.

```text
Private Files -> Local MCP Tool (llama-server) -> Sanitized Summary ----+
                                                                         |
Public Web/Data -> Public MCP (Firecrawl or docs source) -> Evidence ----+-> Gemini Synthesis
                                                                         |
                                             Orchestrated by LangChain --+
```

## Step 1: Spin Up the Private Brain (llama-server)

Start your local model service:

```bash
./llama-server -m ./models/llama-3-8b.gguf --port 8080 --webui-mcp-proxy
```

Publish that local MCP capability into SAM.

Important: in SAM, the access scope for files is enforced by your local MCP tool configuration, not by `sam publish` flags.

```bash
# Start a node in a dedicated federation for this workflow
sam up --federation hybrid-audit &

# Publish a private-docs capability backed by local MCP on :8080
sam publish mcp \
  --federation hybrid-audit \
  --capability private-docs \
  --resource-name private-docs \
  --resource-kind tool \
  --port 8080
```

If you need a safety check before publishing network-visible state:

```bash
sam publish --skill private-docs --mcp-port 8080 --dry-run=client
```

## Step 2: Orchestrate with LangChain + Gemini

LangChain acts as the director:

- route private reads/summarization to local SAM capability
- route public retrieval to a public MCP/web source
- send only sanitized output to Gemini for final synthesis

Example scaffold:

```python
from langchain_google_genai import ChatGoogleGenerativeAI

# NOTE:
# - SAM CLI is request/response; for production orchestration, run a small adapter
#   service that exposes SAM calls as an MCP server transport for LangChain.
# - The snippet below focuses on control flow, not adapter implementation details.

llm = ChatGoogleGenerativeAI(model="gemini-1.5-pro")

private_summary = """
[From local private-docs capability]
Contract summary (sanitized):
- no personal names
- no raw clauses copied
- extracted obligations and controls only
"""

public_evidence = """
[From public retrieval]
Latest EU AI Act obligations for high-risk systems...
"""

prompt = f"""
You are auditing compliance.

Private sanitized summary:
{private_summary}

Public legal evidence:
{public_evidence}

Return:
1) compliance gaps
2) required remediation
3) confidence and citations
"""

result = llm.invoke(prompt)
print(result.content)
```

## Step 3: End-to-End User Journey

1. Local Filter
The private document is processed locally by your `private-docs` capability. The output is sanitized (PII removed, trade secrets abstracted, sensitive literals redacted).

2. Public Search
Your public retrieval tool fetches current sources (official policy, docs, standards, legal text).

3. Sovereign Synthesis
Gemini receives only the sanitized private summary plus public evidence and generates the final audit report.

Result: high-quality analysis, with raw private source files never sent to cloud inference.

## Why This Pattern Wins

- Data residency by design: easiest path for GDPR/HIPAA-style constraints.
- Cost efficiency: local model does heavy extraction; cloud model does higher-value synthesis.
- Low infrastructure overhead: SAM supports direct peer connectivity without central gateway dependency.

## Security Controls Checklist

- Use a dedicated federation (`--federation hybrid-audit`).
- Prefer least-privilege capabilities (`private-docs`, not broad wildcard tools).
- Use Biscuit caveats for tool restrictions (for example, allow only `private-docs`).
- Audit tokens and cards before execution:

```bash
sam inspect biscuit "auditor-bot;allow_skill=private-docs"
sam inspect card '{"peer_id":"...","agent_card":{...}}'
sam call private-docs --message "summarize" --dry-run=client
```

## BATS E2E Test Skeleton

```bash
@test "E2E: Hybrid audit keeps secret local" {
  sam up --federation testing-hybrid &

  echo "Secret: Don't tell the cloud" > /tmp/secret.txt

  # Assume local MCP tool on :8080 is configured to read /tmp only
  sam publish mcp \
    --federation testing-hybrid \
    --capability private-docs \
    --resource-name private-docs \
    --port 8080 &

  run python3 ./scripts/hybrid_test.py

  assert_output --partial "Summary of document"
  refute_output --partial "Don't tell the cloud"
}
```

## Operational Notes

- `sam publish mcp` exposes an MCP endpoint reachable through SAM; it does not configure filesystem ACLs.
- Keep your local MCP implementation responsible for strict path allowlists.
- For reproducibility, pin model version and prompt templates used for sanitization.

## Next Steps

- Read [CLI Reference](../cli/reference.md) for exact command flags.
- Read [Biscuit Authorization](../concepts/biscuit.md) for capability caveats.
- Read [Testing Guide](../testing.md) to integrate this flow into CI.
