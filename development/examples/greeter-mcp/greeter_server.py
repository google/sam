"""Greeter MCP backend exposed by node C in the local dev mesh."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("greeter", host="0.0.0.0", port=7778)


@mcp.tool()
def hello(name: str) -> str:
    """Return a friendly greeting."""
    return f"Hello, {name}!"


@mcp.tool()
def shout(text: str) -> str:
    """Return text uppercased with a trailing exclamation mark."""
    return f"{text.upper()}!"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
