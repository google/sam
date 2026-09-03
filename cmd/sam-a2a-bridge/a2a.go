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
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
)

type bridgeConfig struct {
	sidecarURL string
	token      string
}

// meshURL is the sidecar's raw egress path for one remote a2a service.
func (c bridgeConfig) meshURL(peer, service string) string {
	return strings.TrimRight(c.sidecarURL, "/") + "/sam/" + url.PathEscape(peer) + "/a2a/" + url.PathEscape(service)
}

type sendAgentTaskParams struct {
	Peer           string         `json:"peer" jsonschema:"Peer ID of the node hosting the agent"`
	Service        string         `json:"service" jsonschema:"Name of the a2a service registered on that peer"`
	Message        string         `json:"message,omitempty" jsonschema:"Plain-text message for the agent; optional if data or file_path is set"`
	Data           map[string]any `json:"data,omitempty" jsonschema:"Structured JSON payload sent to the agent as an A2A DataPart"`
	FilePath       string         `json:"file_path,omitempty" jsonschema:"Local file to attach; sent to the agent as bytes, max 5 MB"`
	FileName       string         `json:"file_name,omitempty" jsonschema:"Name shown to the agent for the attached file (default: the file's base name)"`
	RequiredLabels string         `json:"required_labels,omitempty" jsonschema:"Comma-separated key=value labels the provider must have attested (e.g. region=eu-west-1); the local node refuses fail-closed before any data leaves it"`
	ContextID      string         `json:"context_id,omitempty" jsonschema:"Continue an existing conversation context"`
	TaskID         string         `json:"task_id,omitempty" jsonschema:"Reply into an existing task, e.g. one in state input-required"`
}

const maxAttachmentBytes = 5 << 20

// buildParts builds the message parts in a fixed order (text, data, file) so
// wire output is deterministic across calls with the same params.
func buildParts(p sendAgentTaskParams) ([]*a2a.Part, error) {
	var parts []*a2a.Part
	if p.Message != "" {
		parts = append(parts, a2a.NewTextPart(p.Message))
	}
	if p.Data != nil {
		parts = append(parts, a2a.NewDataPart(p.Data))
	}
	if p.FilePath != "" {
		filePart, err := fileToPart(p.FilePath, p.FileName)
		if err != nil {
			return nil, err
		}
		parts = append(parts, filePart)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("nothing to send: set message, data, or file_path")
	}
	return parts, nil
}

// fileToPart reads path into a raw Part; the SDK's Part has no dedicated file
// constructor, so filename/mediaType are set directly on the returned Part.
func fileToPart(path, nameOverride string) (*a2a.Part, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxAttachmentBytes {
		return nil, fmt.Errorf("file %s is %d bytes; attachment cap is %d", path, info.Size(), maxAttachmentBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	name := nameOverride
	if name == "" {
		name = filepath.Base(path)
	}
	mimeType := mime.TypeByExtension(filepath.Ext(name))
	if mimeType == "" {
		mimeType = http.DetectContentType(data)
	}
	part := a2a.NewRawPart(data)
	part.Filename = name
	part.MediaType = mimeType
	return part, nil
}

type getAgentTaskParams struct {
	Peer    string `json:"peer" jsonschema:"Peer ID of the node hosting the agent"`
	Service string `json:"service" jsonschema:"Name of the a2a service registered on that peer"`
	TaskID  string `json:"task_id" jsonschema:"ID of the task to fetch"`
}

type taskResult struct {
	TaskID    string `json:"task_id"`
	ContextID string `json:"context_id"`
	State     string `json:"state"`
	Text      string `json:"text"`
}

func newMeshClient(ctx context.Context, cfg bridgeConfig, peer, service, requiredLabels string) (*a2aclient.Client, error) {
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &samTransport{
			base:           http.DefaultTransport,
			token:          cfg.token,
			requiredLabels: requiredLabels,
		},
	}
	return a2aclient.NewFromEndpoints(ctx,
		[]*a2a.AgentInterface{a2a.NewAgentInterface(cfg.meshURL(peer, service), a2a.TransportProtocolJSONRPC)},
		a2aclient.WithJSONRPCTransport(httpClient),
	)
}

func sendAgentTask(ctx context.Context, cfg bridgeConfig, p sendAgentTaskParams) (taskResult, error) {
	client, err := newMeshClient(ctx, cfg, p.Peer, p.Service, p.RequiredLabels)
	if err != nil {
		return taskResult{}, err
	}
	defer client.Destroy()

	parts, err := buildParts(p)
	if err != nil {
		return taskResult{}, err
	}
	var msg *a2a.Message
	if p.TaskID != "" || p.ContextID != "" {
		msg = a2a.NewMessageForTask(a2a.MessageRoleUser,
			a2a.TaskInfo{TaskID: a2a.TaskID(p.TaskID), ContextID: p.ContextID}, parts...)
	} else {
		msg = a2a.NewMessage(a2a.MessageRoleUser, parts...)
	}
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: msg})
	if err != nil {
		return taskResult{}, err
	}
	return toTaskResult(result), nil
}

func getAgentTask(ctx context.Context, cfg bridgeConfig, p getAgentTaskParams) (taskResult, error) {
	client, err := newMeshClient(ctx, cfg, p.Peer, p.Service, "")
	if err != nil {
		return taskResult{}, err
	}
	defer client.Destroy()

	task, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: a2a.TaskID(p.TaskID)})
	if err != nil {
		return taskResult{}, err
	}
	return toTaskResult(task), nil
}

// toTaskResult flattens the SDK's Message|Task union into the 4 fields a
// harness needs; a direct Message reply is final, hence state "completed".
func toTaskResult(result any) taskResult {
	switch v := result.(type) {
	case *a2a.Message:
		return taskResult{
			TaskID:    string(v.TaskID),
			ContextID: v.ContextID,
			State:     "completed",
			Text:      textOf(v.Parts),
		}
	case *a2a.Task:
		out := taskResult{TaskID: string(v.ID), ContextID: v.ContextID, State: string(v.Status.State)}
		if v.Status.Message != nil {
			out.Text = textOf(v.Status.Message.Parts)
		}
		if out.Text == "" {
			var texts []string
			for _, artifact := range v.Artifacts {
				if s := textOf(artifact.Parts); s != "" {
					texts = append(texts, s)
				}
			}
			out.Text = strings.Join(texts, "\n")
		}
		return out
	}
	return taskResult{}
}

// textOf joins the text of every part; a2a.Part is a concrete struct (not an
// interface) so Text() is universal, unlike the docs-only sketch assumed.
func textOf(parts a2a.ContentParts) string {
	var texts []string
	for _, part := range parts {
		if s := part.Text(); s != "" {
			texts = append(texts, s)
		}
	}
	return strings.Join(texts, "\n")
}
