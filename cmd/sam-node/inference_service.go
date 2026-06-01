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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/openai/openai-go"
)

// InferenceService provides intelligent LLM gateway features: traffic routing
// and token usage tracking for OpenAI-compatible endpoints.
type InferenceService struct {
	baseService
	backendURL *url.URL
}

func (s *InferenceService) Init(ctx context.Context) error {
	switch x := s.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		u, err := url.Parse(x.TargetUrl)
		if err != nil {
			return fmt.Errorf("invalid inference backend URL %q: %w", x.TargetUrl, err)
		}
		s.backendURL = u
		s.handler = s.newInferenceProxy()
	case *api.RegisterServiceRequest_Command:
		return fmt.Errorf("command-based backends are not supported for InferenceService")
	default:
		return fmt.Errorf("unsupported backend type %T for InferenceService", s.backend)
	}
	return nil
}

func (s *InferenceService) newInferenceProxy() http.Handler {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "")
			}
		},
		Transport: &inferenceTransport{
			backend: s.backendURL,
			base:    http.DefaultTransport,
		},
	}
}

type inferenceTransport struct {
	backend *url.URL
	base    http.RoundTripper
}

func (t *inferenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attemptReq := req.Clone(req.Context())
	attemptReq.Header.Del("Accept-Encoding") // Prevent gzipped response from breaking token tracking

	attemptReq.URL.Scheme = t.backend.Scheme
	attemptReq.URL.Host = t.backend.Host
	attemptReq.URL.Path = singleJoiningSlash(t.backend.Path, req.URL.Path)
	if t.backend.RawQuery == "" || attemptReq.URL.RawQuery == "" {
		attemptReq.URL.RawQuery = t.backend.RawQuery + attemptReq.URL.RawQuery
	} else {
		attemptReq.URL.RawQuery = t.backend.RawQuery + "&" + attemptReq.URL.RawQuery
	}
	attemptReq.Host = t.backend.Host

	resp, err := t.base.RoundTrip(attemptReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		peerID := getPeerID(req)
		isSSE := strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
		resp.Body = newInterceptingReader(resp.Body, peerID, isSSE)
	}

	return resp, nil
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func getPeerID(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	if remoteAddr != "" {
		if _, err := peer.Decode(remoteAddr); err == nil {
			return remoteAddr
		}
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			if _, err := peer.Decode(host); err == nil {
				return host
			}
			// Only trust X-Peer-Id if request comes from local loopback / trusted localhost source
			if host == "127.0.0.1" || host == "::1" || host == "localhost" {
				if peerHeader := r.Header.Get("X-Peer-Id"); peerHeader != "" {
					return peerHeader
				}
			}
		}
	}
	return "unknown"
}

type interceptingReader struct {
	body io.ReadCloser
	pw   *io.PipeWriter
	done chan struct{}
}

func newInterceptingReader(body io.ReadCloser, peerID string, isSSE bool) io.ReadCloser {
	pr, pw := io.Pipe()
	ir := &interceptingReader{
		body: body,
		pw:   pw,
		done: make(chan struct{}),
	}

	go func() {
		defer func() { _ = pr.Close() }()
		defer close(ir.done)
		parseResponseStream(pr, peerID, isSSE)
	}()

	return ir
}

func (ir *interceptingReader) Read(p []byte) (n int, err error) {
	n, err = ir.body.Read(p)
	if n > 0 {
		_, _ = ir.pw.Write(p[:n])
	}
	if err != nil {
		_ = ir.pw.CloseWithError(err)
	}
	return n, err
}

func (ir *interceptingReader) Close() error {
	err := ir.body.Close()
	_ = ir.pw.CloseWithError(io.EOF)
	return err
}

func parseResponseStream(r io.Reader, peerID string, isSSE bool) {
	if isSSE {
		parseSSEResponse(r, peerID)
	} else {
		parseJSONResponse(r, peerID)
	}
}

func parseJSONResponse(r io.Reader, peerID string) {
	var resp openai.ChatCompletion
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return
	}
	if resp.JSON.Usage.Valid() && (resp.Usage.PromptTokens > 0 || resp.Usage.CompletionTokens > 0) {
		recordTokens(peerID, resp.Model, int(resp.Usage.PromptTokens), int(resp.Usage.CompletionTokens))
	}
}

func parseSSEResponse(r io.Reader, peerID string) {
	reader := bufio.NewReader(r)
	var model string
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if err == io.EOF {
				break
			}
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			if err == io.EOF {
				break
			}
			continue
		}
		dataContent := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataContent == "[DONE]" {
			break
		}

		var chunk openai.ChatCompletionChunk
		if err := json.Unmarshal([]byte(dataContent), &chunk); err == nil {
			if chunk.Model != "" {
				model = chunk.Model
			}
			if chunk.JSON.Usage.Valid() && (chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0) {
				recordTokens(peerID, model, int(chunk.Usage.PromptTokens), int(chunk.Usage.CompletionTokens))
				break
			}
		}
		if err == io.EOF {
			break
		}
	}
}
