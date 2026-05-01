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
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	socketPath := flag.String("socket", "", "Path to Unix domain socket")
	toolName := flag.String("tool", "get_mesh_info", "Tool to call")
	toolArgs := flag.String("args", "{}", "JSON arguments for the tool")
	timoutArgs := flag.Int("timeout", 10, "Timeout in seconds")
	flag.Parse()

	if *socketPath == "" {
		log.Fatal("Must specify -socket")
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if timoutArgs != nil {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(*timoutArgs)*time.Second)
	} else {
		ctx = context.Background()
	}
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("Received signal, shutting down...")
		cancel()
	}()

	// Override default HTTP client transport to use Unix socket
	http.DefaultClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", *socketPath)
		},
	}

	// Create MCP client
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-test-client",
		Version: "0.1.0",
	}, nil)

	// Connect to server using the URL (host is ignored by custom dialer)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://localhost/mcp"}, nil)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Failed to close session: %v", err)
		}
	}()

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
