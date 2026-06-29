import asyncio
import os
import sys
from sam_mcp.client import SamClient

async def main():
    url = os.environ.get("SAM_MCP_URL", "http://sam-node-1:8080/mcp")
    print(f"Connecting to {url}")
    try:
        async with SamClient(server_url=url) as client:
            # Test get_tools
            tools = await client.get_tools()
            print(f"TOOLS_COUNT:{len(tools)}")
            
            # Test call_tool (get_mesh_info is a standard tool in sam-node)
            result = await client.call_tool("get_mesh_info", {})
            print(f"CALL_RESULT:{result}")
            
            sys.exit(0)
    except Exception as e:
        import traceback
        print(f"ERROR:{e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
