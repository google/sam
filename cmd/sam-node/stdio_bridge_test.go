// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
package main

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// newPipeBridge returns a StdioBridge wired to two in-memory pipes so tests
// can drive stdin/stdout without a real subprocess.
func newPipeBridge() (*StdioBridge, *io.PipeWriter, *bytes.Buffer) {
	stdoutReader, stdoutWriter := io.Pipe()
	stdinBuf := &bytes.Buffer{}
	b := &StdioBridge{
		stdin:  nopWriteCloser{stdinBuf},
		stdout: stdoutReader,
	}
	b.Start()
	return b, stdoutWriter, stdinBuf
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func TestStdioBridge_SubscribeReceivesLines(t *testing.T) {
	b, stdoutWriter, _ := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	ch, unsub := b.Subscribe()
	defer unsub()

	go func() {
		_, _ = stdoutWriter.Write([]byte("hello\nworld\n"))
	}()

	want := []string{"hello", "world"}
	for _, w := range want {
		select {
		case got := <-ch:
			if got != w {
				t.Fatalf("Subscribe: got %q, want %q", got, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Subscribe: timed out waiting for %q", w)
		}
	}
}

func TestStdioBridge_UnsubscribeIsIdempotent(t *testing.T) {
	b, stdoutWriter, _ := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	_, unsub := b.Subscribe()
	unsub()
	unsub() // must not panic
}

func TestStdioBridge_SendWritesToStdin(t *testing.T) {
	b, stdoutWriter, stdinBuf := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	if err := b.Send([]byte(`{"jsonrpc":"2.0","id":1}`)); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	got := stdinBuf.String()
	want := `{"jsonrpc":"2.0","id":1}` + "\n"
	if got != want {
		t.Fatalf("Send: stdin got %q, want %q", got, want)
	}
}
