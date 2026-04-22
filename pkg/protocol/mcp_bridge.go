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
	"errors"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"sam/pkg/economy"
	"sam/pkg/identity"
	"sam/pkg/reputation"
)

const MCPProtocolID = "/sam/mcp/1.0.0"

// MCPConnector opens a local MCP JSON-RPC transport endpoint.
type MCPConnector interface {
	Open(ctx context.Context) (mcp.Transport, error)
}

// BridgeOpenRequest is the stream preface required before MCP proxying starts.
type BridgeOpenRequest struct {
	BiscuitToken string `json:"biscuit_token"`
	Amount       int64  `json:"amount"`
	Asset        string `json:"asset"`
	Nonce        string `json:"nonce"`
	Payer        string `json:"payer,omitempty"`
	Payee        string `json:"payee,omitempty"`
	Capability   string `json:"capability"`
}

// MCPBridge proxies inbound libp2p streams to a local MCP endpoint.
//
// Before proxying, it verifies micropayment authorization using economy.Verifier.
type MCPBridge struct {
	host      host.Host
	verifier  economy.Verifier
	connector MCPConnector
}

// NewMCPBridge creates a new MCP bridge and installs the stream handler.
func NewMCPBridge(h host.Host, verifier economy.Verifier, connector MCPConnector) (*MCPBridge, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	if verifier == nil {
		return nil, fmt.Errorf("economy verifier is nil")
	}
	if connector == nil {
		return nil, fmt.Errorf("mcp connector is nil")
	}

	b := &MCPBridge{host: h, verifier: verifier, connector: connector}
	if err := identity.EnsurePassportAuth(h, ""); err != nil {
		return nil, fmt.Errorf("installing passport auth: %w", err)
	}
	h.SetStreamHandler(MCPProtocolID, b.handleInbound)
	return b, nil
}

// Open opens an outbound MCP stream and sends the bridge preface.
func (b *MCPBridge) Open(ctx context.Context, peerID peer.ID, req BridgeOpenRequest) (network.Stream, error) {
	if eval := reputation.DefaultEvaluator(); eval != nil && eval.IsNegative(peerID.String()) {
		return nil, fmt.Errorf("refusing MCP stream to negatively-rated peer %s", peerID)
	}
	if _, err := identity.EnsureAuthenticatedPeer(ctx, b.host, peerID); err != nil {
		return nil, fmt.Errorf("passport authentication failed for %s: %w", peerID, err)
	}
	stream, err := b.host.NewStream(ctx, peerID, MCPProtocolID)
	if err != nil {
		return nil, fmt.Errorf("opening MCP stream: %w", err)
	}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		_ = stream.Reset()
		return nil, fmt.Errorf("writing bridge preface: %w", err)
	}
	return stream, nil
}

func (b *MCPBridge) handleInbound(stream network.Stream) {
	defer func() { _ = stream.Close() }()
	if _, err := identity.EnsureAuthenticatedPeer(context.Background(), b.host, stream.Conn().RemotePeer()); err != nil {
		_ = writeBridgeError(stream, fmt.Errorf("passport authentication required: %w", err))
		return
	}

	reader := bufio.NewReader(stream)

	var openReq BridgeOpenRequest
	// Read exactly one JSON preface frame (newline-delimited). Using json.Decoder
	// directly on the stream can buffer bytes from the next MCP message and cause
	// proxy stalls.
	line, err := reader.ReadBytes('\n')
	if err != nil {
		_ = writeBridgeError(stream, fmt.Errorf("reading bridge preface: %w", err))
		return
	}
	if err := json.Unmarshal(line, &openReq); err != nil {
		_ = writeBridgeError(stream, fmt.Errorf("invalid bridge preface: %w", err))
		return
	}
	if openReq.BiscuitToken == "" {
		_ = writeBridgeError(stream, economy.ErrMissingBiscuitToken)
		return
	}
	if openReq.Amount <= 0 {
		_ = writeBridgeError(stream, economy.ErrInvalidMicropayAmount)
		return
	}
	if openReq.Asset == "" {
		_ = writeBridgeError(stream, economy.ErrMissingMicropayAsset)
		return
	}
	if openReq.Nonce == "" {
		_ = writeBridgeError(stream, economy.ErrMissingMicropayNonce)
		return
	}

	verifyReq := economy.VerifyRequest{
		Token:  openReq.BiscuitToken,
		Method: "STREAM",
		Path:   MCPProtocolID,
		Payment: economy.Micropayment{
			Amount:     openReq.Amount,
			Asset:      openReq.Asset,
			Nonce:      openReq.Nonce,
			Payer:      openReq.Payer,
			Payee:      openReq.Payee,
			Capability: openReq.Capability,
		},
	}
	ctx := context.Background()
	if _, err := b.verifier.Verify(ctx, verifyReq); err != nil {
		_ = writeBridgeError(stream, fmt.Errorf("%w: %v", economy.ErrVerifierDeniedRequest, err))
		return
	}
	if att := reputation.DefaultAttestor(); att != nil {
		_ = att.PublishWithProtocol(context.Background(), stream.Conn().RemotePeer().String(), 1, MCPProtocolID)
	}

	local, err := b.connector.Open(ctx)
	if err != nil {
		_ = writeBridgeError(stream, fmt.Errorf("opening local MCP endpoint: %w", err))
		return
	}

	remote := &mcp.IOTransport{
		Reader: &readCloser{Reader: reader, Closer: stream},
		Writer: stream,
	}
	if err := proxyMCPMessages(ctx, remote, local); err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, mcp.ErrConnectionClosed) {
			_ = stream.Reset()
		}
	}
}

func writeBridgeError(w io.Writer, err error) error {
	return json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: err.Error()})
}

type readCloser struct {
	io.Reader
	io.Closer
}

func proxyMCPMessages(ctx context.Context, remote mcp.Transport, local mcp.Transport) error {
	remoteConn, err := remote.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connecting remote MCP transport: %w", err)
	}
	defer func() { _ = remoteConn.Close() }()

	localConn, err := local.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connecting local MCP transport: %w", err)
	}
	defer func() { _ = localConn.Close() }()

	errCh := make(chan error, 2)
	go forwardMCP(ctx, remoteConn, localConn, errCh)
	go forwardMCP(ctx, localConn, remoteConn, errCh)

	err1 := <-errCh
	err2 := <-errCh

	if err := normalizeProxyError(err1); err != nil {
		return err
	}
	if err := normalizeProxyError(err2); err != nil {
		return err
	}
	return nil
}

func forwardMCP(ctx context.Context, src mcp.Connection, dst mcp.Connection, errCh chan<- error) {
	for {
		msg, err := src.Read(ctx)
		if err != nil {
			errCh <- err
			return
		}
		if err := dst.Write(ctx, msg); err != nil {
			errCh <- err
			return
		}
	}
}

func normalizeProxyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, mcp.ErrConnectionClosed) {
		return nil
	}
	return err
}
