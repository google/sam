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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	coreprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"sam/pkg/economy"
	"sam/pkg/identity"
	"sam/pkg/reputation"
)

const A2AProtocolID coreprotocol.ID = "/sam/a2a/1.0.0"

const (
	FailureTypeLiveness = "Liveness"
	FailureTypeProtocol = "Protocol"
	FailureTypeRemote   = "Remote"
	FailureTypeInternal = "Internal"
)

// Observer receives task health callbacks after every A2A attempt.
type Observer interface {
	OnSuccess(peerID string, latency time.Duration)
	OnFailure(peerID string, errorType string)
}

// NopObserver intentionally drops all callbacks.
type NopObserver struct{}

func (NopObserver) OnSuccess(string, time.Duration) {}
func (NopObserver) OnFailure(string, string)        {}

// LivenessError reports that the remote peer was unreachable or dropped during call.
type LivenessError struct {
	PeerID string
	Err    error
}

func (e *LivenessError) Error() string {
	if e == nil {
		return "liveness error"
	}
	if strings.TrimSpace(e.PeerID) == "" {
		return fmt.Sprintf("peer unreachable: %v", e.Err)
	}
	return fmt.Sprintf("peer %s unreachable: %v", e.PeerID, e.Err)
}

func (e *LivenessError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ExecuteRequest contains all data needed for one outbound A2A task.
type ExecuteRequest struct {
	Target     peer.AddrInfo
	Capability string
	Biscuit    string
	Payment    economy.Micropayment
	MCPRequest json.RawMessage
}

type a2aHeader struct {
	Biscuit    string               `json:"biscuit"`
	Capability string               `json:"capability,omitempty"`
	Payment    economy.Micropayment `json:"payment"`
}

// FederationGate controls which inbound peers are allowed to execute A2A tasks.
// It is called with the requester's peer ID and the requested capability.
// Return nil to allow the stream; return an error to drop it.
type FederationGate interface {
	Allow(ctx context.Context, peerID string, capability string) error
}

// AllowAllGate is a FederationGate that accepts every peer (default, open mesh).
type AllowAllGate struct{}

func (AllowAllGate) Allow(_ context.Context, _ string, _ string) error {
	return nil
}

// IsAllowAllGate reports whether g is the permissive default gate implementation.
func IsAllowAllGate(g FederationGate) bool {
	switch g.(type) {
	case AllowAllGate, *AllowAllGate:
		return true
	default:
		return false
	}
}

// A2AService serves /sam/a2a/1.0 and forwards JSON-RPC over a local MCP connector.
type A2AService struct {
	host      host.Host
	observer  Observer
	mcp       MCPConnector
	gate      FederationGate
	skillGate *economy.BiscuitSkillGate
}

// A2AServiceOption configures an A2AService.
type A2AServiceOption func(*A2AService)

// WithFederationGate installs an identity gate that filters inbound streams by
// requester PeerID before processing any A2A payload.
func WithFederationGate(g FederationGate) A2AServiceOption {
	return func(s *A2AService) { s.gate = g }
}

// WithSkillGate installs a Biscuit skill-caveat gate that drops streams whose
// token does not include an allow_skill caveat matching the requested capability.
func WithSkillGate(g *economy.BiscuitSkillGate) A2AServiceOption {
	return func(s *A2AService) { s.skillGate = g }
}

// NewA2AService registers a handler for /sam/a2a/1.0 on host h.
func NewA2AService(h host.Host, connector MCPConnector, observer Observer, opts ...A2AServiceOption) (*A2AService, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	if connector == nil {
		return nil, fmt.Errorf("mcp connector is nil")
	}
	if observer == nil {
		observer = NopObserver{}
	}
	if err := identity.EnsurePassportAuth(h, ""); err != nil {
		return nil, fmt.Errorf("installing passport auth: %w", err)
	}
	s := &A2AService{host: h, observer: observer, mcp: connector, gate: AllowAllGate{}}
	for _, o := range opts {
		o(s)
	}
	h.SetStreamHandler(A2AProtocolID, s.handleStream)
	return s, nil
}

// Close unregisters the A2A handler from the host.
func (s *A2AService) Close() {
	if s == nil || s.host == nil {
		return
	}
	s.host.RemoveStreamHandler(A2AProtocolID)
}

// Preflight performs liveness and quick protocol-negotiation checks.
func Preflight(ctx context.Context, h host.Host, target peer.AddrInfo) error {
	if h == nil {
		return fmt.Errorf("host is nil")
	}
	if target.ID == "" {
		return fmt.Errorf("target peer ID is required")
	}
	if err := h.Connect(ctx, target); err != nil {
		return &LivenessError{PeerID: target.ID.String(), Err: err}
	}
	probe, err := h.NewStream(ctx, target.ID, A2AProtocolID)
	if err != nil {
		return &LivenessError{PeerID: target.ID.String(), Err: err}
	}
	_ = probe.Close()
	return nil
}

// Execute performs one outbound A2A task and returns the remote JSON-RPC response.
func Execute(ctx context.Context, h host.Host, req ExecuteRequest, observer Observer) (json.RawMessage, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	if req.Target.ID == "" {
		return nil, fmt.Errorf("target peer ID is required")
	}
	if strings.TrimSpace(req.Biscuit) == "" {
		return nil, fmt.Errorf("biscuit token is required")
	}
	payload := []byte(strings.TrimSpace(string(req.MCPRequest)))
	if len(payload) == 0 {
		return nil, fmt.Errorf("mcp request is required")
	}
	if _, err := jsonrpc.DecodeMessage(payload); err != nil {
		return nil, fmt.Errorf("invalid mcp request JSON-RPC payload: %w", err)
	}

	if observer == nil {
		observer = NopObserver{}
	}
	peerID := req.Target.ID.String()
	started := time.Now()
	if err := h.Connect(ctx, req.Target); err != nil {
		observer.OnFailure(peerID, FailureTypeLiveness)
		return nil, &LivenessError{PeerID: peerID, Err: err}
	}
	if err := identity.AuthenticatePeerPassport(ctx, h, req.Target.ID); err != nil {
		observer.OnFailure(peerID, FailureTypeProtocol)
		return nil, fmt.Errorf("passport authentication failed for %s: %w", peerID, err)
	}

	if err := Preflight(ctx, h, req.Target); err != nil {
		observer.OnFailure(peerID, FailureTypeLiveness)
		return nil, err
	}
	if eval := reputation.DefaultEvaluator(); eval != nil && eval.IsNegative(peerID) {
		observer.OnFailure(peerID, FailureTypeProtocol)
		return nil, fmt.Errorf("refusing A2A call to negatively-rated peer %s", peerID)
	}

	stream, err := h.NewStream(ctx, req.Target.ID, A2AProtocolID)
	if err != nil {
		observer.OnFailure(peerID, FailureTypeLiveness)
		return nil, &LivenessError{PeerID: peerID, Err: err}
	}
	defer func() { _ = stream.Close() }()

	// Propagate the caller's deadline to the stream so that all subsequent
	// reads and writes respect the context timeout even after the stream is
	// open (bufio reads don't accept a context directly).
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	// Also wire up context cancellation so a manual cancel (no deadline) also
	// kills the stream promptly.
	ctx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	go func() {
		<-ctx.Done()
		_ = stream.SetDeadline(time.Now())
	}()

	header := a2aHeader{
		Biscuit:    strings.TrimSpace(req.Biscuit),
		Capability: strings.TrimSpace(req.Capability),
		Payment:    req.Payment,
	}
	if strings.TrimSpace(header.Payment.Capability) == "" {
		header.Payment.Capability = header.Capability
	}

	w := bufio.NewWriter(stream)
	if err := json.NewEncoder(w).Encode(header); err != nil {
		observer.OnFailure(peerID, FailureTypeProtocol)
		return nil, fmt.Errorf("writing A2A header: %w", err)
	}
	if _, err := w.Write(append(payload, '\n')); err != nil {
		observer.OnFailure(peerID, classifyFailure(err))
		return nil, wrapRuntimeLiveness(req.Target.ID, err)
	}
	if err := w.Flush(); err != nil {
		observer.OnFailure(peerID, classifyFailure(err))
		return nil, wrapRuntimeLiveness(req.Target.ID, err)
	}

	r := bufio.NewReader(stream)
	line, err := r.ReadBytes('\n')
	if err != nil {
		observer.OnFailure(peerID, classifyFailure(err))
		return nil, wrapRuntimeLiveness(req.Target.ID, err)
	}
	resp := bytesTrimSpace(line)
	if len(resp) == 0 {
		observer.OnFailure(peerID, FailureTypeProtocol)
		return nil, fmt.Errorf("empty A2A response from %s", peerID)
	}
	if remoteErr := decodeA2AError(resp); remoteErr != "" {
		observer.OnFailure(peerID, FailureTypeRemote)
		return nil, fmt.Errorf("remote A2A error from %s: %s", peerID, remoteErr)
	}
	if _, err := jsonrpc.DecodeMessage(resp); err != nil {
		observer.OnFailure(peerID, FailureTypeProtocol)
		return nil, fmt.Errorf("invalid A2A response JSON-RPC payload from %s: %w", peerID, err)
	}

	observer.OnSuccess(peerID, time.Since(started))
	if att := reputation.DefaultAttestor(); att != nil {
		_ = att.Publish(context.Background(), peerID, 1)
	}
	return json.RawMessage(resp), nil
}

func (s *A2AService) handleStream(stream network.Stream) {
	defer func() { _ = stream.Close() }()

	peerID := stream.Conn().RemotePeer().String()
	started := time.Now()
	fail := func(errType string, err error) {
		s.observer.OnFailure(peerID, errType)
		if err != nil {
			_ = writeA2AError(stream, err)
		}
	}

	reader := bufio.NewReader(stream)

	headerLine, err := reader.ReadBytes('\n')
	if err != nil {
		// Liveness preflight opens and closes a probe stream without payload.
		if errors.Is(err, io.EOF) {
			return
		}
		fail(classifyFailure(err), fmt.Errorf("reading A2A header: %w", err))
		return
	}
	var header a2aHeader
	if err := json.Unmarshal(bytesTrimSpace(headerLine), &header); err != nil {
		fail(FailureTypeProtocol, fmt.Errorf("invalid A2A header: %w", err))
		return
	}
	if strings.TrimSpace(header.Biscuit) == "" {
		fail(FailureTypeProtocol, fmt.Errorf("missing biscuit token"))
		return
	}
	claims, err := identity.EnsureAuthenticatedPeer(context.Background(), s.host, stream.Conn().RemotePeer())
	if err != nil {
		fail(FailureTypeProtocol, fmt.Errorf("passport authentication required: %w", err))
		return
	}

	// Identity gate: verify the requester's PeerID is allowed in this federation
	// before forwarding any payload to the local MCP backend.
	authCtx := withAuthenticatedPassportClaims(context.Background(), claims)
	if err := s.gate.Allow(authCtx, peerID, strings.TrimSpace(header.Capability)); err != nil {
		fail(FailureTypeProtocol, fmt.Errorf("federation gate denied peer %s: %w", peerID, err))
		return
	}

	requestLine, err := reader.ReadBytes('\n')

	// Zero-Trust Biscuit: verify the token's allow_skill caveat before processing.
	if s.skillGate != nil {
		capability := strings.TrimSpace(header.Capability)
		if skillErr := s.skillGate.CheckSkill(context.Background(), header.Biscuit, capability); skillErr != nil {
			fail(FailureTypeProtocol, fmt.Errorf("skill caveat check failed: %w", skillErr))
			return
		}
	}

	if err != nil {
		fail(classifyFailure(err), fmt.Errorf("reading MCP request frame: %w", err))
		return
	}
	requestBytes := bytesTrimSpace(requestLine)
	msg, err := jsonrpc.DecodeMessage(requestBytes)
	if err != nil {
		fail(FailureTypeProtocol, fmt.Errorf("decoding MCP JSON-RPC request: %w", err))
		return
	}

	transport, err := s.mcp.Open(context.Background())
	if err != nil {
		fail(FailureTypeInternal, fmt.Errorf("opening local MCP transport: %w", err))
		return
	}
	conn, err := transport.Connect(context.Background())
	if err != nil {
		fail(FailureTypeInternal, fmt.Errorf("connecting local MCP transport: %w", err))
		return
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Write(context.Background(), msg); err != nil {
		fail(FailureTypeInternal, fmt.Errorf("writing local MCP request: %w", err))
		return
	}
	respMsg, err := conn.Read(context.Background())
	if err != nil {
		fail(FailureTypeInternal, fmt.Errorf("reading local MCP response: %w", err))
		return
	}
	respBytes, err := jsonrpc.EncodeMessage(respMsg)
	if err != nil {
		fail(FailureTypeInternal, fmt.Errorf("encoding MCP JSON-RPC response: %w", err))
		return
	}

	writer := bufio.NewWriter(stream)
	if _, err := writer.Write(append(respBytes, '\n')); err != nil {
		fail(classifyFailure(err), fmt.Errorf("writing A2A response: %w", err))
		return
	}
	if err := writer.Flush(); err != nil {
		fail(classifyFailure(err), fmt.Errorf("flushing A2A response: %w", err))
		return
	}

	s.observer.OnSuccess(peerID, time.Since(started))
	if att := reputation.DefaultAttestor(); att != nil {
		_ = att.PublishWithProtocol(context.Background(), peerID, 1, string(A2AProtocolID))
	}
}

func writeA2AError(w io.Writer, err error) error {
	if err == nil {
		err = fmt.Errorf("a2a request failed")
	}
	return json.NewEncoder(w).Encode(struct {
		JSONRPC string `json:"jsonrpc"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID any `json:"id"`
	}{
		JSONRPC: "2.0",
		Error: struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{Code: -32001, Message: err.Error()},
		ID: nil,
	})
}

func wrapRuntimeLiveness(pid peer.ID, err error) error {
	if err == nil {
		return nil
	}
	if classifyFailure(err) == FailureTypeLiveness {
		return &LivenessError{PeerID: pid.String(), Err: err}
	}
	return err
}

func classifyFailure(err error) string {
	if err == nil {
		return FailureTypeInternal
	}
	var livenessErr *LivenessError
	if errors.As(err, &livenessErr) {
		return FailureTypeLiveness
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return FailureTypeLiveness
	case strings.Contains(msg, "connection reset"):
		return FailureTypeLiveness
	case strings.Contains(msg, "stream reset"):
		return FailureTypeLiveness
	case strings.Contains(msg, "broken pipe"):
		return FailureTypeLiveness
	case strings.Contains(msg, "no good addresses"):
		return FailureTypeLiveness
	case strings.Contains(msg, "deadline exceeded"):
		return FailureTypeLiveness
	case strings.Contains(msg, "eof"):
		return FailureTypeLiveness
	default:
		return FailureTypeProtocol
	}
}

func decodeA2AError(payload []byte) string {
	var rpcOut struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &rpcOut); err == nil {
		if msg := strings.TrimSpace(rpcOut.Error.Message); msg != "" {
			return msg
		}
	}

	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return ""
	}
	return strings.TrimSpace(out.Error)
}

func bytesTrimSpace(in []byte) []byte {
	return bytes.TrimSpace(in)
}
