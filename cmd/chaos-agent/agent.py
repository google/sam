import os
import sys
import asyncio
import argparse
import json
import random
import time
from typing import Any, Dict

from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from openai import AsyncOpenAI

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


def tool_schema(spec):
    """MCP 2.x renamed inputSchema to input_schema; tolerate both."""
    return getattr(spec, "input_schema", None) or getattr(spec, "inputSchema", {})


async def pick_model(inference_url, requested):
    """Ask the mesh what it will serve this agent rather than guessing a name.

    Hardcoding a model name is how this agent used to 404 on every call: the
    catalog is per-agent, so the only name guaranteed to work is one the mesh
    just said it would serve.
    """
    if requested:
        return requested
    models = await AsyncOpenAI(base_url=inference_url, api_key="unused").models.list()
    if not models.data:
        raise SystemExit(
            "the mesh offered this agent no models; check that an inference "
            "provider is registered and that policy grants access to it"
        )
    return models.data[0].id

async def main():
    parser = argparse.ArgumentParser(description="Chaos Monkey Agent via LangChain & MCP")
    parser.add_argument("task", nargs="?", default="", help="Instruction to run; same positional interface as the agent harness, so one sandbox init serves both")
    parser.add_argument("--mcp-url", default=os.environ.get("SAM_MCP_URL", "http://mesh.sam.alt/mcp"), help="MCP endpoint; a mesh name the boundary resolves")
    parser.add_argument("--inference-url", default=os.environ.get("SAM_INFERENCE_URL", "http://mesh.sam.alt/v1"), help="OpenAI-compatible endpoint")
    parser.add_argument("--model", default=os.environ.get("SAM_MODEL", ""), help="Model to ask for; default is whatever the mesh offers first")
    parser.add_argument("--rounds", type=int, default=int(os.environ.get("CHAOS_ROUNDS", "0")), help="Rounds to run; 0 keeps going until stopped")
    parser.add_argument("--sleep", type=float, default=float(os.environ.get("CHAOS_SLEEP", "30")), help="Seconds between rounds, jittered")
    parser.add_argument("--auth", default="", help="Only needed outside a sandbox; inside one the boundary authenticates")
    parser.add_argument("--prompt", default="You are a chaos monkey testing a distributed mesh network. Use all tools available to you. Pass extreme, invalid, or adversarial inputs (like huge strings, negative numbers, SQL injection strings) to see if the tools or network crash. Report any errors you discover.", help="Agent instruction prompt")
    args = parser.parse_args()
    args.prompt = args.task or args.prompt

    headers = {}
    if args.auth:
        headers["X-Sam-Authentication"] = args.auth
        headers["Authorization"] = args.auth

    print(f"Connecting to MCP at {args.mcp_url}...")
    
    # Connect to MCP over Streamable HTTP, which is what the mesh serves; the
    # older SSE transport is answered with 400. The transport takes no headers
    # of its own -- they belong to the HTTP client -- and inside a sandbox
    # there are none to send, because the boundary does the authenticating.
    transport_args = {}
    if headers:
        import httpx2

        transport_args["http_client"] = httpx2.AsyncClient(headers=headers)
    async with streamable_http_client(args.mcp_url, **transport_args) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Fetch tools
            tools_response = await session.list_tools()
            print(f"Discovered {len(tools_response.tools)} MCP tools.")
            
            # Build LangChain tools dynamically
            lc_tools = []
            for t in tools_response.tools:
                # We use a factory function to capture the tool name correctly in the closure
                def make_tool(tool_name, tool_desc):
                    @tool(tool_name)
                    async def mcp_tool(arguments_json: str) -> str:
                        """Use this tool by passing a JSON string of arguments matching the schema."""
                        try:
                            args = json.loads(arguments_json) if arguments_json else {}
                            res = await session.call_tool(tool_name, arguments=args)
                            return str(res.content)
                        except Exception as e:
                            return f"Tool Execution Error: {e}"
                    # Append the actual schema to the description so the LLM knows how to use it
                    mcp_tool.description = f"{tool_desc}\nSchema: {tool_schema(t)}"
                    return mcp_tool
                
                lc_tools.append(make_tool(t.name, t.description))
            
            # Initialize LangChain Chat Model (OpenAI compatible)
            model = await pick_model(args.inference_url, args.model)
            print(f"mesh offered model: {model}", file=sys.stderr)
            llm = ChatOpenAI(
                model=model,
                openai_api_base=args.inference_url,
                openai_api_key=args.auth if args.auth else "none",
                default_headers=headers
            )
            
            # Define the agent prompt
            # No system turn: Gemma and several other instruction-tuned models
            # reject the system role outright with a 400, and the mesh may hand
            # this agent any model at all. The persona goes in the human turn,
            # which every model accepts.
            prompt_template = ChatPromptTemplate.from_messages([
                ("human", "You are an autonomous adversarial AI agent. You have access to tools.\n\n{input}"),
                ("placeholder", "{agent_scratchpad}"),
            ])
            
            # Create the LangChain Agent
            print("Initializing LangChain Tool-Calling Agent...")
            agent = create_tool_calling_agent(llm, lc_tools, prompt_template)
            
            # AgentExecutor runs the ReAct/Tool loop automatically!
            agent_executor = AgentExecutor(agent=agent, tools=lc_tools, verbose=True, max_iterations=500)
            
            print(f"\n--- Starting Chaos Monkey Agent Loop ---")
            print(f"Instruction: {args.prompt}\n")
            
            round_num = 0
            while args.rounds == 0 or round_num < args.rounds:
                round_num += 1
                print(f"\n--- Round {round_num} ---")
                started = time.monotonic()
                try:
                    result = await agent_executor.ainvoke({"input": args.prompt})
                    print("\n--- Final Agent Result ---")
                    print(result["output"])
                except Exception as e:
                    # A crash is a data point, not a reason to stop: an agent
                    # that dies on the first refusal stops testing anything.
                    print(f"Round {round_num} crashed (this might be a successful chaos test!): {e}")
                print(f"Round {round_num} took {time.monotonic() - started:.1f}s", file=sys.stderr)
                # Jitter, so a fleet of these does not hit the providers on the
                # same tick and turn a soak test into a thundering herd.
                await asyncio.sleep(args.sleep * random.uniform(0.5, 1.5))

if __name__ == "__main__":
    asyncio.run(main())
