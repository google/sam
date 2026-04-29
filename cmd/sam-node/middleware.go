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
	"fmt"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

// RequestContext carries the security metadata for a specific stream request
type RequestContext struct {
	PeerID   peer.ID
	User     string
	Group    string
	Protocol protocol.ID
}

// WithBiscuitAuth enforces a Protobuf handshake on a stream before calling the next handler.
func (n *SamNode) WithBiscuitAuth(next network.StreamHandler) network.StreamHandler {
	return func(s network.Stream) {
		defer func() {
			if err := s.Close(); err != nil {
				logger.Errorf("[Auth] Failed to close stream: %v", err)
			}
		}()
		remotePeer := s.Conn().RemotePeer()

		// Read AuthFrame
		reader := msgio.NewVarintReaderSize(s, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			logger.Errorf("[Auth] Failed to read auth frame from %s: %v", remotePeer, err)
			return
		}
		defer reader.ReleaseMsg(msg)

		var authFrame api.AuthFrame
		if err := proto.Unmarshal(msg, &authFrame); err != nil {
			logger.Warnf("[Auth] Invalid auth frame from %s", remotePeer)
			return
		}

		// Verify token
		reqCtx := RequestContext{
			PeerID:   remotePeer,
			User:     "", // Not used in Authorize
			Protocol: s.Protocol(),
		}

		writer := msgio.NewVarintWriter(s)

		if err := n.Authorize(authFrame.Biscuit, reqCtx); err != nil {
			logger.Warnf("[Auth] AuthZ Denied %s: %v", remotePeer, err)
			resp := &api.AuthResponse{Success: false, Error: err.Error()}
			respBytes, _ := proto.Marshal(resp)
			_ = writer.WriteMsg(respBytes)
			return
		}

		// Valid
		resp := &api.AuthResponse{Success: true}
		respBytes, _ := proto.Marshal(resp)
		if err := writer.WriteMsg(respBytes); err != nil {
			logger.Errorf("[Auth] Failed to write ACK to %s: %v", remotePeer, err)
			return
		}

		next(s)
	}
}

func (n *SamNode) Authorize(rawToken []byte, req RequestContext) error {
	b, err := biscuit.Unmarshal(rawToken)
	if err != nil {
		return fmt.Errorf("invalid biscuit: %w", err)
	}

	authorizer, err := b.Authorizer(n.HubPublicKey)
	if err != nil {
		return err
	}

	// Verify that the token is bound to the connecting peer's ID
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(req.PeerID.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		return fmt.Errorf("token is not bound to peer %s", req.PeerID)
	}

	// Inject the current action context (Standard Vocabulary)
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "operation",
			IDs:  []biscuit.Term{biscuit.String(req.Protocol)},
		},
	})

	// Load dynamic policies from store and add them as facts
	policies, err := n.Store.LoadPolicies()
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}
	for _, policyStr := range policies {
		cleanPolicy := strings.TrimRight(strings.TrimSpace(policyStr), ";")
		p, err := parser.FromStringPolicy(cleanPolicy)
		if err != nil {
			return fmt.Errorf("failed to parse policy '%s': %w", policyStr, err)
		}
		authorizer.AddPolicy(p)
	}

	return authorizer.Authorize()
}
