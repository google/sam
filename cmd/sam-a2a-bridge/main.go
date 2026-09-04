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
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	sidecarURL := flag.String("url", "http://localhost:8080", "Sidecar API base URL")
	token := flag.String("token", "", "Authorization Bearer token for protected sidecar endpoints")
	downloadDir := flag.String("download-dir", "", "Directory for files returned by agents (default: ~/.sam/a2a-downloads, created if missing)")
	flag.Parse()

	// A user-supplied dir is used as-is (the caller creates it); only the
	// built-in default is auto-created. Fail fast so a missing dir surfaces
	// at startup, not on the first file-bearing result.
	dir := *downloadDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		dir = filepath.Join(home, ".sam", "a2a-downloads")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatal(err)
		}
	} else if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		log.Fatalf("-download-dir %s is not a usable directory (create it first): %v", dir, err)
	}
	cfg := bridgeConfig{sidecarURL: *sidecarURL, token: *token, downloadDir: dir}
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
		Name: "get_agent_card",
		Description: "Fetch a mesh agent's card, trimmed to essentials: skills with examples, accepted " +
			"input/output MIME types, and streaming support. Use before composing data/file sends.",
	}, mcpTool(cfg, handleGetAgentCard))

	mcp.AddTool(server, &mcp.Tool{
		Name: "send_agent_task",
		Description: "Send a message to an A2A agent on the SAM mesh: plain text (message), structured JSON " +
			"(data), and/or a local file attachment (file_path, max 5 MB) — at least one required. Returns " +
			"immediately with {task_id, context_id, state, text, data?, files?}; received files are saved to " +
			"disk and returned as paths. Poll non-terminal states with get_agent_task. Pass context_id to " +
			"continue a conversation, task_id to reply into a task waiting for input. required_labels makes " +
			"the local node refuse fail-closed unless the provider attested them.",
	}, mcpTool(cfg, handleSendAgentTask))

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_agent_task",
		Description: "Fetch the current state and output of a task previously created with send_agent_task; " +
			"same result shape, including data and files.",
	}, mcpTool(cfg, handleGetAgentTask))

	return server
}

// mcpTool adapts a handler to the go-sdk tool signature, routing errors
// through toolResult so refusals surface as tool errors.
func mcpTool[Params, Result any](cfg bridgeConfig, handler func(context.Context, bridgeConfig, Params) (Result, error)) func(context.Context, *mcp.CallToolRequest, Params) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, p Params) (*mcp.CallToolResult, any, error) {
		res, err := handler(ctx, cfg, p)
		return toolResult(res, err)
	}
}

// toolResult renders errors as tool errors (not protocol errors) so the
// harness model sees refusal text like the labels-gate 403 verbatim.
func toolResult(res any, err error) (*mcp.CallToolResult, any, error) {
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
