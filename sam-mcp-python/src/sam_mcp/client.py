import asyncio
import os
from typing import Any, Dict, List, Optional
from mcp import ClientSession
from mcp.client.sse import sse_client

class SamClient:
    """High-level developer interface for SAM MCP using official SDK."""
    
    def __init__(self, server_url: Optional[str] = None, token: Optional[str] = None):
        if server_url is None:
            server_url = os.environ.get("SAM_MCP_URL", "http://localhost:8080/mcp")
        if token is None:
            token = os.environ.get("SAM_API_TOKEN")
        self.server_url = server_url
        self.token = token
        self.session: Optional[ClientSession] = None
        self._sse_cm = None

    async def connect(self):
        """Connects to the SAM node via SSE."""
        headers = {"Accept": "application/json, text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._sse_cm = sse_client(self.server_url, headers=headers)
        read_stream, write_stream = await self._sse_cm.__aenter__()
        self.session = ClientSession(read_stream, write_stream)
        await self.session.__aenter__()
        await self.session.initialize()

    async def close(self):
        """Closes the connection."""
        if self.session:
            await self.session.__aexit__(None, None, None)
        if self._sse_cm:
            await self._sse_cm.__aexit__(None, None, None)
        self.session = None
        self._sse_cm = None

    async def get_tools(self) -> List[Dict[str, Any]]:
        """Returns available mesh tools."""
        if not self.session:
            raise RuntimeError("Not connected")
        resp = await self.session.list_tools()
        return [t.model_dump() if hasattr(t, "model_dump") else t for t in resp.tools]

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a tool over the mesh."""
        if not self.session:
            raise RuntimeError("Not connected")
        resp = await self.session.call_tool(name, arguments)
        return resp.model_dump() if hasattr(resp, "model_dump") else resp

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
