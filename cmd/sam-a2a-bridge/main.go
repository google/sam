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
	"errors"
	"flag"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	sidecarURL := flag.String("url", "http://localhost:8080", "Sidecar API base URL")
	token := flag.String("token", "", "Authorization Bearer token for protected sidecar endpoints")
	flag.Parse()

	cfg := bridgeConfig{sidecarURL: *sidecarURL, token: *token}
	if err := newBridgeServer(cfg).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

func newBridgeServer(cfg bridgeConfig) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sam-a2a-bridge",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "send_agent_task",
		Description: "Send a text message to an A2A agent on the SAM mesh. Returns immediately with " +
			"{task_id, context_id, state, text}; poll non-terminal states with get_agent_task. " +
			"Pass context_id to continue a conversation, task_id to reply into a task waiting for input. " +
			"required_labels makes the local node refuse fail-closed unless the provider attested them.",
	}, handleSendAgentTask(cfg))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_agent_task",
		Description: "Fetch the current state and output of a task previously created with send_agent_task.",
	}, handleGetAgentTask(cfg))

	return server
}

func handleSendAgentTask(cfg bridgeConfig) func(context.Context, *mcp.CallToolRequest, sendAgentTaskParams) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, p sendAgentTaskParams) (*mcp.CallToolResult, any, error) {
		res, err := sendAgentTask(ctx, cfg, p)
		return toolResult(res, err)
	}
}

func handleGetAgentTask(cfg bridgeConfig) func(context.Context, *mcp.CallToolRequest, getAgentTaskParams) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, p getAgentTaskParams) (*mcp.CallToolResult, any, error) {
		res, err := getAgentTask(ctx, cfg, p)
		return toolResult(res, err)
	}
}

// toolResult renders errors as tool errors (not protocol errors) so the
// harness model sees refusal text like the labels-gate 403 verbatim.
func toolResult(res taskResult, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		text := err.Error()
		var se *sidecarError
		if errors.As(err, &se) {
			text = se.Error()
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: text}},
		}, nil, nil
	}
	out, err := json.Marshal(res)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
	}, nil, nil
}
