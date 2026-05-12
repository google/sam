// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestBridgeTransport_WriteSendsToStdin(t *testing.T) {
	b, stdoutWriter, stdinBuf := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	tr := newBridgeTransport(b)
	conn, err := tr.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	id, _ := jsonrpc.MakeID(float64(1))
	req := &jsonrpc.Request{ID: id, Method: "tools/list"}
	if err := conn.Write(context.Background(), req); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := stdinBuf.String()
	if len(got) == 0 || got[len(got)-1] != '\n' {
		t.Fatalf("Write: expected newline-terminated frame on stdin, got %q", got)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got[:len(got)-1]), &parsed); err != nil {
		t.Fatalf("Write: stdin frame is not valid JSON: %v (raw=%q)", err, got)
	}
	if parsed["method"] != "tools/list" {
		t.Fatalf("Write: method = %v, want tools/list", parsed["method"])
	}
}

func TestBridgeTransport_ReadReceivesFromStdout(t *testing.T) {
	b, stdoutWriter, _ := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	tr := newBridgeTransport(b)
	conn, err := tr.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_, _ = stdoutWriter.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	resp, ok := msg.(*jsonrpc.Response)
	if !ok {
		t.Fatalf("Read: expected *jsonrpc.Response, got %T", msg)
	}
	wantID, _ := jsonrpc.MakeID(float64(1))
	if resp.ID != wantID {
		t.Fatalf("Read: id = %v, want 1", resp.ID)
	}
}

func TestBridgeTransport_CloseUnsubscribes(t *testing.T) {
	b, stdoutWriter, _ := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	tr := newBridgeTransport(b)
	conn, err := tr.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close (second call): %v", err)
	}
}
