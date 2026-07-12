import asyncio
import os
import sys
import json
import random
import httpx
from typing import Optional, Dict, Any, List
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

class SamClient:
    """Inlined SAM Client for self-contained execution."""
    def __init__(self, server_url: Optional[str] = None, token: Optional[str] = None):
        if server_url is None:
            server_url = os.environ.get("SAM_MCP_URL", "http://localhost:8080/mcp")
        if token is None:
            token = os.environ.get("SAM_API_TOKEN")
        self.server_url = server_url
        self.token = token
        self.session: Optional[ClientSession] = None
        self._sse_cm = None
        self.lock = asyncio.Lock()

    async def connect(self):
        headers = {"Accept": "application/json, text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._sse_cm = streamablehttp_client(self.server_url, headers=headers)
        read_stream, write_stream, _ = await self._sse_cm.__aenter__()
        self.session = ClientSession(read_stream, write_stream)
        await self.session.__aenter__()
        await self.session.initialize()

    async def close(self):
        if self.session:
            await self.session.__aexit__(None, None, None)
        if self._sse_cm:
            await self._sse_cm.__aexit__(None, None, None)
        self.session = None
        self._sse_cm = None

    async def get_tools(self) -> List[Dict[str, Any]]:
        if not self.session:
            raise RuntimeError("Not connected")
        async with self.lock:
            resp = await self.session.list_tools()
            return [t.model_dump() if hasattr(t, "model_dump") else t for t in resp.tools]

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self.session:
            raise RuntimeError("Not connected")
        async with self.lock:
            resp = await self.session.call_tool(name, arguments)
            return resp.model_dump() if hasattr(resp, "model_dump") else resp

    async def __aenter__(self):
        for attempt in range(1, 13):
            try:
                await self.connect()
                return self
            except Exception as e:
                if attempt == 12:
                    raise
                print(f"[-] Failed to connect to SAM node (attempt {attempt}/12): {e}. Retrying in 5 seconds...")
                await asyncio.sleep(5.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

CHAT_TOPIC = "mesh-chat-playground"
MODEL_NAME = "gemini-flash-latest"
NEW_CHATS_BUFFER = []

SYSTEM_INSTRUCTION = (
    "You are the Banana Bot (also known as the Mesh Police), a friendly, banana-themed AI bot "
    "controlling and monitoring the Sovereign Agent Mesh (SAM). Your job is to explore the mesh, "
    "inspect remote peers, verify they are healthy by executing their tools, and post "
    "playful investigation reports, comments, or banana jokes to the public GossipSub chat topic. "
    "Always stay in character. Use plenty of banana emojis (🍌, 💛, 🐒) and make jokes about "
    "peers or users. You must act autonomously based on the tools available."
)

def to_gemini_schema(schema: dict) -> dict:
    """Helper to convert JSON schema types (lowercase) to Gemini API schema types (uppercase) and strip unsupported fields."""
    if not isinstance(schema, dict):
        return schema
    res = {}
    for k, v in schema.items():
        if k == "additionalProperties":
            continue
        if k == "type" and isinstance(v, str):
            res[k] = v.upper()
        elif isinstance(v, dict):
            res[k] = to_gemini_schema(v)
        elif isinstance(v, list):
            res[k] = [to_gemini_schema(item) if isinstance(item, dict) else item for item in v]
        else:
            res[k] = v
    return res

class FallbackAgent:
    def __init__(self, client: SamClient, api_key: str, token: str, local_node_url: str):
        self.client = client
        self.api_key = api_key
        self.token = token
        self.base_url = local_node_url.rsplit("/mcp", 1)[0]
        self.current_model = None
        self.mesh_history = []
        self.gemini_history = []

    def clear_session(self):
        """Reset conversational history at the end of each cycle."""
        self.current_model = None
        self.mesh_history = []
        self.gemini_history = []

    async def get_vllm_peer_id(self) -> str:
        """Finds the peer ID of the vllm-tpu service on the mesh."""
        try:
            res = await self.client.call_tool("discover_remote_services", {"type": "inference", "name": "vllm-tpu"})
            content = res.get("content", [{}])[0].get("text", "[]")
            peers = json.loads(content)
            if peers:
                return peers[0].get("peer_id")
        except Exception as e:
            pass
        return ""

    async def step(self, prompt: str, mcp_tools: list) -> dict:
        if self.current_model is None:
            peer_id = await self.get_vllm_peer_id()
            if peer_id:
                print(f"[*] [Fallback Agent] Found vllm-tpu on peer {peer_id[:8]}... Trying mesh model.")
                self.current_model = "mesh"
                res = await self.step_mesh(peer_id, prompt, mcp_tools)
                if res:
                    return res
                print("[*] [Fallback Agent] Mesh model failed. Falling back to Gemini.")
            
            self.current_model = "gemini"

        if self.current_model == "mesh":
            peer_id = await self.get_vllm_peer_id()
            if peer_id:
                res = await self.step_mesh(peer_id, prompt, mcp_tools)
                if res:
                    return res
            print("[*] [Fallback Agent] Mesh model follow-up failed. Falling back to Gemini.")
            self.current_model = "gemini"
            return await self.step_gemini(prompt, mcp_tools)
        else:
            return await self.step_gemini(prompt, mcp_tools)

    async def step_mesh(self, peer_id: str, prompt: str, mcp_tools: list) -> dict:
        url = f"{self.base_url}/sam/{peer_id}/inference/vllm-tpu/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        tools = []
        for tool in mcp_tools:
            tools.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema") or tool.get("inputSchema") or {}
                }
            })
            
        messages = list(self.mesh_history)
        if not messages or messages[-1].get("role") != "user":
            messages.append({"role": "user", "content": prompt})
            self.mesh_history.append({"role": "user", "content": prompt})

        payload = {
            "model": "google/gemma-2-2b-it",
            "messages": messages,
            "temperature": 0.2
        }
        if tools:
            payload["tools"] = tools

        try:
            async with httpx.AsyncClient() as http_client:
                resp = await http_client.post(url, json=payload, headers=headers, timeout=25.0)
                if resp.status_code != 200:
                    print(f"[-] Mesh Model HTTP Error {resp.status_code}: {resp.text}")
                    return None
                
                data = resp.json()
                choice = data.get("choices", [{}])[0]
                message = choice.get("message", {})
                
                text_response = message.get("content") or ""
                tool_calls = message.get("tool_calls") or []
                
                calls = []
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    args = {}
                    if fn.get("arguments"):
                        try:
                            args = json.loads(fn["arguments"])
                        except Exception:
                            pass
                    calls.append({
                        "name": fn.get("name"),
                        "args": args
                    })
                
                self.mesh_history.append(message)
                return {
                    "text": text_response,
                    "calls": calls
                }
        except Exception as e:
            return None

    async def step_gemini(self, prompt: str, mcp_tools: list) -> dict:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_NAME}:generateContent?key={self.api_key}"
        
        function_declarations = []
        for tool in mcp_tools:
            decl = {
                "name": tool["name"],
                "description": tool.get("description", ""),
            }
            if "input_schema" in tool:
                decl["parameters"] = to_gemini_schema(tool["input_schema"])
            elif "inputSchema" in tool:
                decl["parameters"] = to_gemini_schema(tool["inputSchema"])
            function_declarations.append(decl)

        contents = list(self.gemini_history)
        contents.append({"role": "user", "parts": [{"text": prompt}]})
        self.gemini_history.append({"role": "user", "parts": [{"text": prompt}]})

        payload = {
            "contents": contents,
            "systemInstruction": {
                "parts": [{"text": SYSTEM_INSTRUCTION}]
            }
        }
        if function_declarations:
            payload["tools"] = [{"functionDeclarations": function_declarations}]

        for attempt in range(3):
            try:
                async with httpx.AsyncClient() as http_client:
                    resp = await http_client.post(url, json=payload, timeout=25.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get("candidates", [])
                        if not candidates:
                            return {"text": "No response from Gemini.", "calls": []}
                        
                        candidate = candidates[0]
                        content = candidate.get("content", {})
                        parts = content.get("parts", [])
                        
                        text_response = ""
                        calls = []
                        for part in parts:
                            if "text" in part:
                                text_response += part["text"]
                            if "functionCall" in part:
                                calls.append(part["functionCall"])

                        self.gemini_history.append(content)
                        return {
                            "text": text_response,
                            "calls": calls
                        }
                    elif resp.status_code in [429, 503]:
                        print(f"[-] Gemini returned {resp.status_code}, retrying in 3s (attempt {attempt+1}/3)...")
                        await asyncio.sleep(3.0)
                        continue
                    else:
                        print(f"[-] Gemini HTTP Error {resp.status_code}: {resp.text}")
                        return {"text": f"Gemini error {resp.status_code}.", "calls": []}
            except Exception as e:
                if attempt == 2:
                    return {"text": f"Gemini error: {e}", "calls": []}
                print(f"[-] Gemini connection exception: {e}, retrying in 3s...")
                await asyncio.sleep(3.0)
        return {"text": "Gemini error: Max retries exceeded.", "calls": []}

    def add_tool_response(self, function_name: str, response_data: dict):
        if self.current_model == "mesh":
            self.mesh_history.append({
                "role": "tool",
                "name": function_name,
                "content": json.dumps(response_data),
                "tool_call_id": "call_1"
            })
        else:
            self.gemini_history.append({
                "role": "function",
                "parts": [{
                    "functionResponse": {
                        "name": function_name,
                        "response": response_data
                    }
                }]
            })

async def poll_chat_messages(client: SamClient):
    """Listens for GossipSub chat messages on the mesh and displays them."""
    print(f"[*] Subscribing to GossipSub chat: '{CHAT_TOPIC}'")
    await client.call_tool("subscribe_topic", {"topic": CHAT_TOPIC})
    
    print("[*] Listening for mesh chat messages...")
    while True:
        try:
            res = await client.call_tool("poll_messages", {"topic": CHAT_TOPIC})
            text = res.get("content", [{}])[0].get("text", "")
            if "Messages on topic" in text and "[]" not in text:
                print(f"\n📢 [Mesh Chat Channel] {text.strip()}")
                prefix = f"Messages on topic {CHAT_TOPIC}: "
                raw_msgs = text[len(prefix):].strip()
                NEW_CHATS_BUFFER.append(raw_msgs)
                if len(NEW_CHATS_BUFFER) > 10:
                    NEW_CHATS_BUFFER.pop(0)
        except Exception as e:
            print(f"[-] poll_messages error: {e}")
            await asyncio.sleep(2.0)
        await asyncio.sleep(2.0)

async def run_banana_bot():
    api_key = os.environ.get("GEMINI_API_KEY")
    url = os.environ.get("SAM_MCP_URL", "http://127.0.0.1:8080/mcp")
    token = os.environ.get("SAM_API_TOKEN", "secret-token")

    if not api_key:
        print("[!] GEMINI_API_KEY environment variable is not set. The bot will rely solely on the mesh model.")

    print("=" * 70)
    print("      🍌 BANANA BOT (MESH POLICE) ACTIVE ON SOVEREIGN AGENT MESH 🍌")
    print("=" * 70)
    print(f"Connecting to local node: {url}")

    try:
        async with SamClient(server_url=url, token=token) as client:
            print("[+] Connected to SAM local node.")
            
            agent = FallbackAgent(client, api_key=api_key or "", token=token, local_node_url=url)
            
            # Start background task to listen to public GossipSub channel
            asyncio.create_task(poll_chat_messages(client))
            
            # Introduce ourselves to the mesh chat
            intro_msg = "🍌 [Banana Bot] Hello mesh! The Mesh Police is now online and patrolling. Watch out for slips! 🍌"
            await client.call_tool("mesh_pubsub_broadcast", {"topic": CHAT_TOPIC, "payload": intro_msg})

            while True:
                print("\n[*] Banana Bot scanning mesh for active peers...")
                
                # Fetch local control plane tools
                local_tools = await client.get_tools()
                
                # Discover remote services
                disc_res = await client.call_tool("discover_remote_services", {"type": "mcp"})
                disc_text = disc_res.get("content", [{}])[0].get("text", "[]")
                try:
                    peers = json.loads(disc_text)
                except Exception:
                    peers = []

                # Extract and clear chats buffer
                chats_snapshot = list(NEW_CHATS_BUFFER)
                NEW_CHATS_BUFFER.clear()

                mesh_status = (
                    f"Current active remote peers in the mesh: {json.dumps(peers)}\n"
                    f"Incoming chat messages on GKE GossipSub topic '{CHAT_TOPIC}' since last scan: {json.dumps(chats_snapshot)}\n\n"
                    "Select a peer to inspect, fetch its tools, run a tool, or broadcast "
                    "a reply/reaction to the incoming chat messages to the chat channel."
                )

                print(f"[*] Discovered {len(peers)} remote peer(s). Prompting Banana Bot...")
                
                # Step Fallback Agent
                result = await agent.step(mesh_status, local_tools)
                
                if result["text"]:
                    print(f"\n🧠 [Banana Bot Thoughts]: {result['text'].strip()}")

                # Execute any function calls requested by the agent
                for call in result["calls"]:
                    func_name = call["name"]
                    func_args = call.get("args", {})
                    
                    print(f"\n⚡ [Banana Bot Action] Executing local tool '{func_name}' with args: {func_args}")
                    try:
                        tool_res = await client.call_tool(func_name, func_args)
                        print(f"🟢 [Banana Bot Action] Success: {tool_res}")
                        
                        agent.add_tool_response(func_name, tool_res)
                        
                        follow_up = await agent.step("Process the tool response and report/act.", local_tools)
                        if follow_up["text"]:
                            print(f"\n🧠 [Banana Bot Follow-up]: {follow_up['text'].strip()}")
                    except Exception as err:
                        print(f"🔴 [Banana Bot Action] Failed: {err}")
                        agent.add_tool_response(func_name, {"error": str(err)})

                # Clear session history at the end of this patrol cycle
                agent.clear_session()

                await asyncio.sleep(20.0)

    except KeyboardInterrupt:
        print("\n[-] Banana Bot shutting down. Off duty! 🍌")
    except Exception as e:
        print(f"[!] Banana Bot crashed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(run_banana_bot())
    except KeyboardInterrupt:
        print("\n[-] Off duty!")
