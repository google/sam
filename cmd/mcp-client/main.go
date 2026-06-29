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
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	serverURL := flag.String("url", "", "MCP server URL or Sidecar API base URL (e.g. http://localhost:8080/)")
	toolName := flag.String("tool", "", "Tool to call")
	toolArgs := flag.String("args", "{}", "JSON arguments for the tool or discovery parameters")
	timeoutArgs := flag.Int("timeout", 10, "Timeout in seconds")
	listTools := flag.Bool("list", false, "List available tools and exit")
	streamOpt := flag.Bool("stream", false, "Enable streaming mode for service discovery HTTP API")
	tokenOpt := flag.String("token", "", "Authorization Bearer token for protected sidecar endpoints")
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

	if *streamOpt {
		var args map[string]string
		if *toolArgs != "" {
			if err := json.Unmarshal([]byte(*toolArgs), &args); err != nil {
				log.Fatalf("Failed to parse args: %v", err)
			}
		}
		serviceType := args["type"]
		serviceName := args["name"]

		if serviceType == "" {
			log.Fatal("Must specify 'type' in -args (e.g. -args '{\"type\":\"mcp\"}')")
		}

		// Construct URL
		baseURL := strings.TrimSuffix(*serverURL, "/mcp")
		baseURL = strings.TrimSuffix(baseURL, "/")
		if !strings.Contains(baseURL, "/sam/service/discover") {
			baseURL = baseURL + "/sam/service/discover"
		}

		discoveryURL := fmt.Sprintf("%s?type=%s&stream=true", baseURL, serviceType)
		if serviceName != "" {
			discoveryURL = fmt.Sprintf("%s&name=%s", discoveryURL, serviceName)
		}
		if *timeoutArgs > 0 {
			discoveryURL = fmt.Sprintf("%s&timeout=%ds", discoveryURL, *timeoutArgs)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		if *tokenOpt != "" {
			req.Header.Set("Authorization", "Bearer "+*tokenOpt)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("Failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Fatalf("Discovery failed with status: %d, error: %s", resp.StatusCode, string(bodyBytes))
		}

		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err == io.EOF {
				break
			}
			if err != nil {
				if ctx.Err() != nil {
					return // Context canceled
				}
				log.Fatalf("Failed to read stream: %v", err)
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "data:") {
				dataContent := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				fmt.Println(dataContent)
			} else if strings.HasPrefix(line, "event:") {
				fmt.Printf("[%s]\n", strings.TrimSpace(strings.TrimPrefix(line, "event:")))
			}
		}
		return
	}

	// Create MCP client
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-test-client",
		Version: "0.1.0",
	}, nil)

	// Connect to server using the URL
	var mcpTransport mcp.Transport = &mcp.StreamableClientTransport{Endpoint: *serverURL}
	if *tokenOpt != "" {
		mcpTransport = &mcp.StreamableClientTransport{
			Endpoint: *serverURL,
			HTTPClient: &http.Client{
				Transport: &authTransport{
					token:      *tokenOpt,
					underlying: http.DefaultTransport,
				},
			},
		}
	}
	session, err := client.Connect(ctx, mcpTransport, nil)
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

type authTransport struct {
	token      string
	underlying http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request to avoid mutating original request if shared/retried
	reqCopy := req.Clone(req.Context())
	reqCopy.Header.Set("Authorization", "Bearer "+t.token)
	return t.underlying.RoundTrip(reqCopy)
}
