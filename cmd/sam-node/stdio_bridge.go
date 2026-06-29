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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/google/sam/api"
)

type StdioBridge struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	mu      sync.Mutex
	clients map[chan string]bool
	calls   map[string]chan string
}

func (b *StdioBridge) Start() {
	b.clients = make(map[chan string]bool)
	b.calls = make(map[string]chan string)
	go func() {
		scanner := bufio.NewScanner(b.stdout)
		for scanner.Scan() {
			line := scanner.Text()

			b.mu.Lock()
			if len(line) > 0 && line[0] == '{' {
				var msg map[string]any
				if err := json.Unmarshal([]byte(line), &msg); err == nil {
					if idVal, ok := msg["id"]; ok {
						reqIDStr := fmt.Sprintf("%v", idVal)
						if ch, found := b.calls[reqIDStr]; found {
							select {
							case ch <- line:
							default:
							}
						}
					}
				}
			}

			for ch := range b.clients {
				select {
				case ch <- line:
				default:
				}
			}
			b.mu.Unlock()
		}

		b.mu.Lock()
		for ch := range b.clients {
			close(ch)
			delete(b.clients, ch)
		}
		for _, ch := range b.calls {
			close(ch)
		}
		b.calls = make(map[string]chan string)
		b.mu.Unlock()
	}()
}

func (b *StdioBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		ch := make(chan string, 10)
		b.mu.Lock()
		b.clients[ch] = true
		b.mu.Unlock()

		// Flush headers immediately to establish the stream
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		defer func() {
			b.mu.Lock()
			delete(b.clients, ch)
			b.mu.Unlock()
			close(ch)
		}()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-ch:
				if !ok {
					return
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", line); err != nil {
					logger.Errorf("Failed to write to SSE client: %v", err)
					return
				}
				flusher.Flush()
			}
		}
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()

		var msg map[string]any
		isCall := false
		var reqID any
		if err := json.Unmarshal(body, &msg); err == nil {
			if id, ok := msg["id"]; ok {
				isCall = true
				reqID = id
			}
		}

		var ch <-chan string
		var unsub func()
		if isCall {
			reqIDStr := fmt.Sprintf("%v", reqID)
			callCh := make(chan string, 1)
			b.mu.Lock()
			b.calls[reqIDStr] = callCh
			b.mu.Unlock()
			ch = callCh
			unsub = func() {
				b.mu.Lock()
				if existing, ok := b.calls[reqIDStr]; ok && existing == callCh {
					delete(b.calls, reqIDStr)
					close(callCh)
				}
				b.mu.Unlock()
			}
			defer unsub()
		}

		b.mu.Lock()
		_, err = b.stdin.Write(append(body, '\n'))
		b.mu.Unlock()

		if err != nil {
			http.Error(w, "Failed to write to process stdin", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Mcp-Session-Id", "stdio-bridge")

		if !isCall {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		ctx := r.Context()
		select {
		case <-ctx.Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(line))
			return
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Subscribe registers a new subscriber channel for stdout lines and returns
// it along with an idempotent unsubscribe function. Buffered (cap 10); drops
// on slow consumers match the SSE behaviour in ServeHTTP.
func (b *StdioBridge) Subscribe() (<-chan string, func()) {
	ch := make(chan string, 10)
	b.mu.Lock()
	b.clients[ch] = true
	b.mu.Unlock()

	var once sync.Once
	unsub := func() {
		once.Do(func() {
			b.mu.Lock()
			if b.clients[ch] {
				delete(b.clients, ch)
				close(ch)
			}
			b.mu.Unlock()
		})
	}
	return ch, unsub
}

// Send writes data to the child's stdin, appending a newline.
func (b *StdioBridge) Send(data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.stdin.Write(append(data, '\n'))
	return err
}

func createStdioBridgeHandler(cmdBackend *api.CommandBackend) (http.Handler, *exec.Cmd, error) {
	cmd := exec.Command(cmdBackend.Command[0], cmdBackend.Command[1:]...)
	cmd.Env = os.Environ()
	for k, v := range cmdBackend.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	bridge := &StdioBridge{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
	}
	bridge.Start()

	return bridge, cmd, nil
}
