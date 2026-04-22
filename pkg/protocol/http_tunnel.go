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
	"sam/pkg/reputation"
)

const HTTPTunnelProtocolID coreprotocol.ID = "/sam/tunnel/http/1.0"

type HTTPTunnelOpenRequest struct {
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
	if err := identity.EnsurePassportAuth(h, ""); err != nil {
		return nil, fmt.Errorf("installing passport auth: %w", err)
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
	if err := identity.AuthenticatePeerPassport(ctx, h, target); err != nil {
		return nil, fmt.Errorf("passport authentication failed: %w", err)
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
	if resp.Error == "" && resp.StatusCode > 0 && resp.StatusCode < 500 {
		if att := reputation.DefaultAttestor(); att != nil {
			_ = att.PublishWithProtocol(context.Background(), target.String(), 1, string(HTTPTunnelProtocolID))
		}
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

	if err := s.verifyMetadata(context.Background(), stream.Conn().RemotePeer(), &openReq); err != nil {
		_ = json.NewEncoder(stream).Encode(HTTPTunnelResponse{StatusCode: http.StatusForbidden, Error: err.Error()})
		return
	}

	resp := s.forwardLocal(context.Background(), openReq.Request)
	_ = json.NewEncoder(stream).Encode(resp)
}

func (s *HTTPTunnelService) verifyMetadata(ctx context.Context, remotePeer peer.ID, req *HTTPTunnelOpenRequest) error {
	if _, err := identity.EnsureAuthenticatedPeer(ctx, s.host, remotePeer); err != nil {
		return fmt.Errorf("passport authentication required: %w", err)
	}
	if strings.TrimSpace(req.Biscuit) == "" {
		return fmt.Errorf("missing biscuit metadata")
	}
	authValues := req.Request.Headers["Authorization"]
	if len(authValues) == 0 {
		authValues = req.Request.Headers["authorization"]
	}
	if _, err := extractBearerFromValues(authValues); err != nil {
		return err
	}
	if strings.TrimSpace(req.Capability) != "" {
		if err := s.skillGate.CheckSkill(ctx, req.Biscuit, strings.TrimSpace(req.Capability)); err != nil {
			return fmt.Errorf("biscuit denied capability: %w", err)
		}
	}
	return nil
}

func extractBearerFromValues(values []string) (string, error) {
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "Bearer") {
			continue
		}
		token := strings.TrimSpace(parts[1])
		if token == "" {
			return "", fmt.Errorf("bearer token is empty")
		}
		return token, nil
	}
	if len(values) == 0 {
		return "", fmt.Errorf("missing Authorization header")
	}
	return "", fmt.Errorf("Authorization must use Bearer scheme")
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
