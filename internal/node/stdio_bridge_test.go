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

package node

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestStdioBridge_ServeHTTP_GETStreamsBroadcastLines(t *testing.T) {
	b, stdoutWriter, _ := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		b.ServeHTTP(rec, req)
		close(done)
	}()

	// Give the handler a moment to register as a client before writing.
	time.Sleep(50 * time.Millisecond)
	_, _ = stdoutWriter.Write([]byte("hello\n"))
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after ctx was cancelled")
	}

	if got := rec.Body.String(); !strings.Contains(got, "data: hello\n\n") {
		t.Fatalf("SSE body = %q, want it to contain %q", got, "data: hello\n\n")
	}
}

func TestStdioBridge_ServeHTTP_POSTNotificationReturnsAccepted(t *testing.T) {
	b, stdoutWriter, stdinBuf := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	body := `{"jsonrpc":"2.0","method":"notify"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	if got := stdinBuf.String(); got != body+"\n" {
		t.Fatalf("stdin got %q, want %q", got, body+"\n")
	}
}

func TestStdioBridge_ServeHTTP_POSTCallWaitsForMatchingReply(t *testing.T) {
	b, stdoutWriter, _ := newPipeBridge()
	defer func() { _ = stdoutWriter.Close() }()

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		b.ServeHTTP(rec, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	reply := `{"jsonrpc":"2.0","id":1,"result":{}}`
	_, _ = stdoutWriter.Write([]byte(reply + "\n"))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after the matching reply arrived")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != reply {
		t.Fatalf("body = %q, want %q", got, reply)
	}
}
