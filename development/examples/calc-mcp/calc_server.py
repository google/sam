"""Calculator MCP backend exposed by node B in the local dev mesh."""
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
    mcp.run(transport="streamable-http")
