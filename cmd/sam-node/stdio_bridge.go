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
}

func (b *StdioBridge) Start() {
	b.clients = make(map[chan string]bool)
	go func() {
		scanner := bufio.NewScanner(b.stdout)
		for scanner.Scan() {
			line := scanner.Text()
			b.mu.Lock()
			for ch := range b.clients {
				select {
				case ch <- line:
				default:
				}
			}
			b.mu.Unlock()
		}
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
			case line := <-ch:
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

		b.mu.Lock()
		_, err = b.stdin.Write(append(body, '\n'))
		b.mu.Unlock()

		if err != nil {
			http.Error(w, "Failed to write to process stdin", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
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
			delete(b.clients, ch)
			b.mu.Unlock()
			close(ch)
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
