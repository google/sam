import asyncio
import os
import sys
from google import genai
from google.genai import types
from sam_mcp.client import SamClient

# Helper to recursively map MCP (JSON Schema) types to Gemini (OpenAPI Schema) types
def to_gemini_schema(mcp_schema: dict) -> dict:
    if not isinstance(mcp_schema, dict):
        return mcp_schema
    
    gemini_schema = {}
    for k, v in mcp_schema.items():
        if k == "type" and isinstance(v, str):
            # Gemini expects uppercase types (e.g. 'STRING', 'OBJECT')
            gemini_schema[k] = v.upper()
        elif k == "properties" and isinstance(v, dict):
            gemini_schema[k] = {prop_name: to_gemini_schema(prop_val) for prop_name, prop_val in v.items()}
        elif k == "items" and isinstance(v, dict):
            gemini_schema[k] = to_gemini_schema(v)
        else:
            gemini_schema[k] = v
            
    return gemini_schema

async def run_agent():
    # 1. Connect to local SAM Node
    # By default, connects to http://localhost:8080/mcp/events
    print("Connecting to local SAM Node...")
    client = SamClient()
    try:
        await client.connect()
    except Exception as e:
        print(f"Error: Failed to connect to local SAM Node: {e}")
        print("Make sure sam-node is running (e.g. 'sam-node run --bind-addr 127.0.0.1:8080')")
        sys.exit(1)

    print("Successfully connected!")
    
    # 2. Get available tools from the Mesh
    mcp_tools = await client.get_tools()
    print(f"Discovered {len(mcp_tools)} tools in the mesh.")
    for t in mcp_tools:
        print(f" - {t['name']}: {t.get('description', '')}")

    # 3. Build Gemini Tool Declarations
    gemini_functions = []
    for tool in mcp_tools:
        # Build parameters schema
        params_schema = to_gemini_schema(tool.get("inputSchema", {}))
        
        # Define the function declaration
        decl = types.FunctionDeclaration(
            name=tool["name"],
            description=tool.get("description", ""),
            parameters=params_schema
        )
        gemini_functions.append(decl)

    # Wrap function declarations into a Gemini Tool
    gemini_tools = [types.Tool(function_declarations=gemini_functions)]

    # 4. Initialize Gemini Client
    # Requires GEMINI_API_KEY environment variable
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("\nWarning: GEMINI_API_KEY environment variable not set.")
        print("Please export it to run the AI agent: export GEMINI_API_KEY=\"your-key\"")
        await client.close()
        sys.exit(1)

    ai = genai.Client(api_key=api_key)
    # Using the recommended model for function calling
    model_name = "gemini-2.5-flash" 

    print(f"\nInitialized Gemini Agent ({model_name}) with Mesh Tools.")
    print("You can now ask questions! Type 'exit' or 'quit' to stop.")
    print("-" * 60)

    # 5. Interactive Chat Loop
    # We use chat session to maintain history
    chat = ai.chats.create(
        model=model_name,
        config=types.GenerateContentConfig(
            tools=gemini_tools,
            system_instruction="You are an AI agent running inside the Sovereign Agent Mesh (SAM). "
                               "You have access to tools registered by other peers in the mesh. "
                               "If a user asks you to perform a task, check if there's a tool that can solve it. "
                               "Always prioritize using tools to explore or interact with the mesh."
        )
    )

    while True:
        try:
            user_input = input("\nYou > ")
            if user_input.lower() in ["exit", "quit"]:
                break
            if not user_input.strip():
                continue

            # Send message to Gemini
            response = chat.send_message(user_input)

            # Handle function calling loop (Gemini might make multiple calls sequentially)
            while response.function_calls:
                for call in response.function_calls:
                    print(f"\n[Agent wants to call tool: {call.name} with args: {call.args}]")
                    
                    # Convert Gemini args Map to normal dict
                    args = dict(call.args) if call.args else {}
                    
                    # Call the tool via local SAM Node
                    try:
                        result = await client.call_tool(call.name, args)
                        print(f"[Tool Result]: {result}")
                        
                        # Send tool response back to Gemini
                        response = chat.send_message(
                            types.Part.from_function_response(
                                name=call.name,
                                response={"result": result}
                            )
                        )
                    except Exception as tool_err:
                        print(f"[Tool Error]: {tool_err}")
                        # Send error back to model so it knows it failed
                        response = chat.send_message(
                            types.Part.from_function_response(
                                name=call.name,
                                response={"error": str(tool_err)}
                            )
                        )

            # Print Gemini's final response text
            if response.text:
                print(f"\nAgent > {response.text}")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error during interaction: {e}")

    await client.close()
    print("\nDisconnected. Goodbye!")

if __name__ == "__main__":
    asyncio.run(run_agent())
