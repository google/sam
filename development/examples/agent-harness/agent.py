"""A minimal agent harness that owns nothing but its own logic.

This is the whole point of running an agent on SAM, in one file: there is no
model endpoint to configure, no API key to mount, no tool server to deploy
alongside it, and no network to lock down afterwards. The harness asks the mesh
for a model and for tools, and the mesh decides what this particular agent is
allowed to have.

Three things are worth noticing while reading it.

It holds no credentials. There is no key in this file, in its environment, or
in the sandbox it runs in. The gateway outside the sandbox knows which agent
this is and says so on every request; an agent that could assert its own
identity could borrow somebody else's.

It addresses services by name, not by address. `mesh.sam.alt` is not in DNS and
has no route to it. The name is resolved by the boundary, which picks a
provider according to policy, so the agent never learns where anything runs and
cannot be pinned to a host that later moves.

It is an ordinary HTTP client. Nothing here is SAM-specific: the OpenAI SDK and
the MCP SDK are used exactly as they would be anywhere. That is deliberate. If
running on the mesh required a special client, every existing agent would need
rewriting to move onto it.
"""

import argparse
import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from openai import AsyncOpenAI

# The mesh's own name for itself. Not DNS, not routable, and deliberately not
# configurable: an agent that can be pointed somewhere else is one misconfigured
# environment variable away from talking to something nobody authorised.
MESH = "http://mesh.sam.alt"

SYSTEM_PROMPT = """You are an agent running on a Sovereign Agent Mesh.

You have tools available to you that were granted by mesh policy. Use them when
they help. If a tool is refused, that is policy, not a bug: say so and continue
without it rather than retrying.

Answer the user's task directly and stop when it is done."""


async def discover_tools(session):
    """Ask the mesh what this agent is allowed to use.

    The list is not fixed at build time and is not the same for every agent:
    two agents on the same node can see different tools, because the mesh
    answers according to who is asking.
    """
    listed = await session.list_tools()
    tools = []
    for tool in listed.tools:
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    # input_schema, not inputSchema: the SDK renamed it in 2.0
                    # along with the transport, and the old name raises an
                    # AttributeError only once a tool is actually discovered.
                    "parameters": tool.input_schema
                    or {"type": "object", "properties": {}},
                },
            }
        )
    return tools


async def call_tool(session, name, arguments):
    """Run one tool call, turning a refusal into an answer the model can use.

    A denied tool must come back as text the model can reason about. Raising
    here would end the run, which would turn "you may not do that" into a
    crash and teach the model nothing.
    """
    try:
        result = await session.call_tool(name, arguments=arguments)
        return "".join(
            block.text for block in result.content if hasattr(block, "text")
        ) or str(result.content)
    except Exception as exc:  # noqa: BLE001 - any failure is a result to reason about
        return f"tool call failed: {exc}"


async def pick_model(client, requested):
    """Resolve the model to ask for, preferring whatever the mesh actually offers.

    An agent that hardcodes a model name is an agent that needs configuration,
    which is the thing this harness is trying not to need. The catalog is
    already per-agent -- it lists what this agent's policy allows -- so asking
    it is both the simplest option and the correct one.
    """
    if requested:
        return requested
    models = await client.models.list()
    if not models.data:
        raise SystemExit(
            "the mesh offered this agent no models; check that an inference "
            "provider is registered and that policy grants access to it"
        )
    return models.data[0].id


async def run(task, model, max_steps):
    # No api_key that means anything: the gateway authenticates this agent to
    # the mesh. The SDK requires the argument, so it gets a placeholder.
    client = AsyncOpenAI(base_url=f"{MESH}/v1", api_key="unused")

    model = await pick_model(client, model)
    print(f"mesh offered model: {model}", file=sys.stderr)

    # Streamable HTTP, which is what the mesh serves. The older SSE transport
    # is answered with 400, and that arrives late enough to look like a network
    # problem rather than a protocol one.
    async with streamable_http_client(f"{MESH}/mcp") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await discover_tools(session)
            print(f"mesh granted {len(tools)} tools: "
                  f"{', '.join(t['function']['name'] for t in tools) or 'none'}",
                  file=sys.stderr)

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task},
            ]

            for step in range(max_steps):
                response = await client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools or None,
                )
                choice = response.choices[0].message
                messages.append(choice.model_dump(exclude_none=True))

                if not choice.tool_calls:
                    return choice.content or ""

                for call in choice.tool_calls:
                    arguments = json.loads(call.function.arguments or "{}")
                    print(f"step {step + 1}: {call.function.name}({arguments})",
                          file=sys.stderr)
                    output = await call_tool(session, call.function.name, arguments)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": output,
                        }
                    )

            return "stopped: reached the step limit without finishing"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "task",
        nargs="?",
        default="Describe the tools you have and what each is for.",
        help="What the agent should do",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("SAM_MODEL", ""),
        help="Model to ask the mesh for; default is whatever the mesh offers first",
    )
    parser.add_argument("--max-steps", type=int, default=10)
    args = parser.parse_args()

    print(asyncio.run(run(args.task, args.model, args.max_steps)))


if __name__ == "__main__":
    main()
