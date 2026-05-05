import asyncio
import os
import sys
from sam_mcp.client import SamClient

async def main():
    # Connect to the local SAM node's MCP SSE endpoint
    # By default, sam-node listens at 127.0.0.1:8080
    url = os.environ.get("SAM_MCP_URL", "http://127.0.0.1:8080/mcp/events")
    print(f"Connecting to SAM Node at {url}")

    try:
        async with SamClient(server_url=url) as client:
            # Discover available tools provided by the SAM node
            tools = await client.get_tools()
            print(f"Discovered {len(tools)} tools:")
            for tool in tools:
                print(f" - {tool['name']}: {tool['description']}")

            # Call the get_mesh_info tool to get information about the mesh
            print("\nCalling get_mesh_info tool...")
            result = await client.call_tool("get_mesh_info", {})
            print("Result:")
            print(result)

    except Exception as e:
        print(f"Error connecting to SAM Node: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
