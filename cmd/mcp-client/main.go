// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	serverURL := flag.String("url", "", "MCP server URL (e.g. http://localhost:8080/)")
	toolName := flag.String("tool", "", "Tool to call")
	toolArgs := flag.String("args", "{}", "JSON arguments for the tool")
	timeoutArgs := flag.Int("timeout", 10, "Timeout in seconds")
	listTools := flag.Bool("list", false, "List available tools and exit")
	flag.Parse()

	if *serverURL == "" {
		log.Fatal("Must specify -url")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutArgs)*time.Second)
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("Received signal, shutting down...")
		cancel()
	}()

	// Create MCP client
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-test-client",
		Version: "0.1.0",
	}, nil)

	// Connect to server using the URL
	session, err := client.Connect(ctx, &mcp.SSEClientTransport{Endpoint: *serverURL}, nil)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Failed to close session: %v", err)
		}
	}()

	if *listTools || *toolName == "" {
		tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			log.Fatalf("ListTools failed: %v", err)
		}
		for _, t := range tools.Tools {
			fmt.Printf("%s\t%s\n", t.Name, t.Description)
		}
		return
	}

	var args map[string]any
	if *toolArgs != "" {
		if err := json.Unmarshal([]byte(*toolArgs), &args); err != nil {
			log.Fatalf("Failed to parse args: %v", err)
		}
	}

	// Call tool
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      *toolName,
		Arguments: args,
	})
	if err != nil {
		log.Fatalf("CallTool failed: %v", err)
	}

	for _, content := range result.Content {
		if textContent, ok := content.(*mcp.TextContent); ok {
			fmt.Println(textContent.Text)
		}
	}
}
