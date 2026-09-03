"""Gemini-backed A2A chat agent hosted by a node in the local dev mesh."""
import json
import os
import time

from google.protobuf.json_format import MessageToDict

import uvicorn
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Part,
)
from google import genai
from google.genai import types
from starlette.applications import Starlette

PORT = 7777
MODEL = os.environ.get("GEMINI_MODEL", "models/gemini-3.5-flash-lite")

# Typed channel for "I need the user to answer first": a function call is
# schema-enforced, unlike a magic reply prefix the model may forget or misquote.
ASK_USER = types.FunctionDeclaration(
    name="ask_user",
    description="Ask the user a clarifying question you need answered before you can complete the request.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={"question": types.Schema(type=types.Type.STRING)},
        required=["question"],
    ),
)

class ChatExecutor(AgentExecutor):
    """One Gemini chat session per A2A contextId; the session carries the history."""

    def __init__(self):
        self.gemini = genai.Client()
        self.chats = {}
        self.pending_question = set()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        chat = self.chats.get(context.context_id)
        if chat is None:
            # Gemini 3 Flash defaults to thinking_level=high, which dominates latency.
            chat = self.gemini.aio.chats.create(
                model=MODEL,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="minimal"),
                    tools=[types.Tool(function_declarations=[ASK_USER])],
                ),
            )
            self.chats[context.context_id] = chat
        prompt = context.get_user_input()
        data_parts = [
            MessageToDict(part.data)
            for part in context.message.parts
            if part.WhichOneof("content") == "data"
        ]
        if data_parts:
            # Text-first agent: structured payloads reach Gemini as a labeled block.
            prompt += "\n[structured data]: " + json.dumps(data_parts)
        gemini_parts = [prompt]
        for part in context.message.parts:
            if part.WhichOneof("content") != "raw":
                continue
            media = part.media_type or "application/octet-stream"
            if media.startswith("text/"):
                # Text attachments read best as prompt text, not opaque blobs.
                gemini_parts[0] += f"\n[attached file {part.filename}]:\n" + part.raw.decode("utf-8", "replace")
            else:
                gemini_parts.append(types.Part.from_bytes(data=part.raw, mime_type=media))
        # A dangling ask_user call must be answered in-history; the user's
        # reply IS the tool response.
        if context.context_id in self.pending_question:
            self.pending_question.discard(context.context_id)
            gemini_parts[0] = types.Part.from_function_response(
                name="ask_user", response={"answer": gemini_parts[0]}
            )
        started = time.monotonic()
        reply = await chat.send_message(gemini_parts)
        print(
            f"[chat] context={context.context_id} gemini took "
            f"{time.monotonic() - started:.1f}s usage={reply.usage_metadata}",
            flush=True,
        )
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        calls = reply.function_calls or []
        if calls and calls[0].name == "ask_user":
            self.pending_question.add(context.context_id)
            question = str(calls[0].args.get("question", ""))
            await updater.requires_input(updater.new_agent_message([Part(text=question)]))
        else:
            await updater.complete(updater.new_agent_message([Part(text=reply.text or "")]))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass


agent_card = AgentCard(
    name="chat",
    description="Gemini-backed conversational agent; remembers the conversation per contextId",
    version="0.1.0",
    capabilities=AgentCapabilities(streaming=False),
    default_input_modes=["text/plain", "application/json", "application/pdf", "image/png", "image/jpeg"],
    default_output_modes=["text/plain"],
    skills=[
        AgentSkill(
            id="chat",
            name="chat",
            description="Multi-turn small talk",
            tags=["chat"],
            examples=["hi, my name is Ada", "what is my name?"],
        )
    ],
    supported_interfaces=[
        AgentInterface(
            protocol_binding="JSONRPC",
            protocol_version="1.0",
            url=f"http://127.0.0.1:{PORT}/",
        )
    ],
)

handler = DefaultRequestHandler(
    agent_executor=ChatExecutor(),
    task_store=InMemoryTaskStore(),
    agent_card=agent_card,
)
# Starlette over FastAPI: the SDK generates the routes, so FastAPI would add nothing.
# JSON-RPC at "/": the mesh card regeneration drops URL subpaths, so clients land on the root.
app = Starlette(
    routes=[
        *create_jsonrpc_routes(request_handler=handler, rpc_url="/"),
        *create_agent_card_routes(agent_card=agent_card),
    ]
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
