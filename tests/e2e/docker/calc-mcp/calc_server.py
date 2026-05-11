"""Tiny MCP backend exposed by Node B as a 'calculator' service."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calculator", host="0.0.0.0", port=7777)


@mcp.tool()
def add(a: float, b: float) -> float:
    """Return a + b."""
    return a + b


@mcp.tool()
def multiply(a: float, b: float) -> float:
    """Return a * b."""
    return a * b


if __name__ == "__main__":
    # Streamable-HTTP exposes a single /mcp endpoint that handles JSON-RPC.
    mcp.run(transport="streamable-http")
