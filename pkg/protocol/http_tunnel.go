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

package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	coreprotocol "github.com/libp2p/go-libp2p/core/protocol"

	"sam/pkg/economy"
	"sam/pkg/identity"
)

const HTTPTunnelProtocolID coreprotocol.ID = "/sam/tunnel/http/1.0"

type HTTPTunnelOpenRequest struct {
	Vouch      *identity.Vouch   `json:"vouch,omitempty"`
	Biscuit    string            `json:"biscuit"`
	Capability string            `json:"capability,omitempty"`
	Request    HTTPTunnelRequest `json:"request"`
}

type HTTPTunnelRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    []byte              `json:"body,omitempty"`
}

type HTTPTunnelResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       []byte              `json:"body,omitempty"`
	Error      string              `json:"error,omitempty"`
}

type HTTPTunnelService struct {
	host      host.Host
	endpoint  *url.URL
	client    *http.Client
	skillGate *economy.BiscuitSkillGate
}

type HTTPTunnelServiceOption func(*HTTPTunnelService)

func WithHTTPTunnelSkillGate(g *economy.BiscuitSkillGate) HTTPTunnelServiceOption {
	return func(s *HTTPTunnelService) { s.skillGate = g }
}

func NewHTTPTunnelService(h host.Host, endpoint string, opts ...HTTPTunnelServiceOption) (*HTTPTunnelService, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return nil, fmt.Errorf("endpoint is required")
	}
	u, err := url.Parse(e)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("endpoint must include scheme and host")
	}

	s := &HTTPTunnelService{
		host:      h,
		endpoint:  u,
		client:    &http.Client{Timeout: 60 * time.Second},
		skillGate: economy.NewBiscuitSkillGate(nil),
	}
	for _, opt := range opts {
		opt(s)
	}

	h.SetStreamHandler(HTTPTunnelProtocolID, s.handleStream)
	return s, nil
}

func (s *HTTPTunnelService) Close() {
	if s == nil || s.host == nil {
		return
	}
	s.host.RemoveStreamHandler(HTTPTunnelProtocolID)
}

func TunnelHTTP(ctx context.Context, h host.Host, target peer.ID, req HTTPTunnelOpenRequest) (*HTTPTunnelResponse, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	if target == "" {
		return nil, fmt.Errorf("target peer id is required")
	}
	if strings.TrimSpace(req.Biscuit) == "" {
		return nil, fmt.Errorf("biscuit is required")
	}
	if req.Vouch == nil {
		return nil, fmt.Errorf("vouch is required")
	}
	if strings.TrimSpace(req.Request.Method) == "" {
		return nil, fmt.Errorf("request method is required")
	}

	stream, err := h.NewStream(ctx, target, HTTPTunnelProtocolID)
	if err != nil {
		return nil, fmt.Errorf("opening HTTP tunnel stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	w := bufio.NewWriter(stream)
	if err := json.NewEncoder(w).Encode(req); err != nil {
		return nil, fmt.Errorf("writing tunnel preface: %w", err)
	}
	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("flushing tunnel preface: %w", err)
	}

	var resp HTTPTunnelResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading tunnel response: %w", err)
	}
	return &resp, nil
}

func (s *HTTPTunnelService) handleStream(stream network.Stream) {
	defer func() { _ = stream.Close() }()

	var openReq HTTPTunnelOpenRequest
	if err := json.NewDecoder(stream).Decode(&openReq); err != nil {
		_ = json.NewEncoder(stream).Encode(HTTPTunnelResponse{StatusCode: http.StatusBadRequest, Error: fmt.Sprintf("invalid preface: %v", err)})
		return
	}

	remotePeer := stream.Conn().RemotePeer().String()
	if err := s.verifyMetadata(context.Background(), remotePeer, &openReq); err != nil {
		_ = json.NewEncoder(stream).Encode(HTTPTunnelResponse{StatusCode: http.StatusForbidden, Error: err.Error()})
		return
	}

	resp := s.forwardLocal(context.Background(), openReq.Request)
	_ = json.NewEncoder(stream).Encode(resp)
}

func (s *HTTPTunnelService) verifyMetadata(ctx context.Context, remotePeer string, req *HTTPTunnelOpenRequest) error {
	if req.Vouch == nil {
		return fmt.Errorf("missing vouch metadata")
	}
	if req.Vouch.IsExpired() {
		return fmt.Errorf("vouch is expired")
	}
	if strings.TrimSpace(req.Vouch.PeerID) != remotePeer {
		return fmt.Errorf("vouch peer mismatch")
	}
	if strings.TrimSpace(req.Biscuit) == "" {
		return fmt.Errorf("missing biscuit metadata")
	}
	if strings.TrimSpace(req.Capability) != "" {
		if err := s.skillGate.CheckSkill(ctx, req.Biscuit, strings.TrimSpace(req.Capability)); err != nil {
			return fmt.Errorf("biscuit denied capability: %w", err)
		}
	}
	return nil
}

func (s *HTTPTunnelService) forwardLocal(ctx context.Context, treq HTTPTunnelRequest) HTTPTunnelResponse {
	method := strings.TrimSpace(treq.Method)
	if method == "" {
		method = http.MethodGet
	}

	targetURL := *s.endpoint
	if treq.Path != "" {
		rawPath := treq.Path
		if !strings.HasPrefix(rawPath, "/") {
			rawPath = "/" + rawPath
		}
		if ref, err := url.Parse(rawPath); err == nil {
			targetURL = *s.endpoint.ResolveReference(ref)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL.String(), strings.NewReader(string(treq.Body)))
	if err != nil {
		return HTTPTunnelResponse{StatusCode: http.StatusBadRequest, Error: fmt.Sprintf("building local request: %v", err)}
	}
	for key, vals := range treq.Headers {
		for _, val := range vals {
			req.Header.Add(key, val)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return HTTPTunnelResponse{StatusCode: http.StatusBadGateway, Error: fmt.Sprintf("calling local endpoint: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return HTTPTunnelResponse{StatusCode: http.StatusBadGateway, Error: fmt.Sprintf("reading local response: %v", err)}
	}

	return HTTPTunnelResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       body,
	}
}
