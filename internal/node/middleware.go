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
	"crypto/ed25519"
	"fmt"
	"sync/atomic"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

// RequestContext carries the security metadata for a specific stream request
type RequestContext struct {
	PeerID   peer.ID
	User     string
	Group    string
	Protocol string
	Target   string
}

// trackingStream wraps a network.Stream to count bytes read and written.
type trackingStream struct {
	network.Stream
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

func (t *trackingStream) Read(p []byte) (n int, err error) {
	n, err = t.Stream.Read(p)
	t.bytesRead.Add(int64(n))
	return n, err
}
func (t *trackingStream) Write(p []byte) (n int, err error) {
	n, err = t.Stream.Write(p)
	t.bytesWritten.Add(int64(n))
	return n, err
}

// WithBiscuitAuth enforces a Protobuf handshake on a stream before calling the next handler.
func (n *SamNode) WithBiscuitAuth(next func(network.Stream, RequestContext)) network.StreamHandler {
	return func(s network.Stream) {
		ts := &trackingStream{Stream: s}
		remotePeer := s.Conn().RemotePeer()
		var reqCtx RequestContext

		defer func() {
			target := reqCtx.Target
			if target == "" {
				target = "unauthenticated_or_failed"
			}
			logger.Infow("Stream Accounting",
				"peer_id", remotePeer.String(),
				"target", target,
				"protocol", reqCtx.Protocol,
				"bytes_read", ts.bytesRead.Load(),
				"bytes_written", ts.bytesWritten.Load(),
			)
			if err := ts.Close(); err != nil {
				logger.Debugf("[Auth] Failed to close stream: %v", err)
			}
		}()

		if !n.rateLimiter.Allow(remotePeer.String()) {
			logger.Warnf("[Auth] Rate limit exceeded for %s, dropping connection", remotePeer)
			_ = ts.Reset()
			return
		}

		// Read AuthFrame
		reader := msgio.NewVarintReaderSize(ts, 1024*64)
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

		reqCtx = RequestContext{
			PeerID:   remotePeer,
			User:     "", // Not used in Authorize
			Protocol: string(ts.Protocol()),
			Target:   authFrame.TargetService,
		}

		writer := msgio.NewVarintWriter(ts)

		err = n.VerifyBiscuitToken(authFrame.Biscuit, reqCtx)
		if err != nil {
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

		next(ts, reqCtx)
	}
}

// VerifyBiscuitToken checks revocation, cache, and evaluates the token against trusted keys and local policies.
func (n *SamNode) VerifyBiscuitToken(biscuitBytes []byte, reqCtx RequestContext) error {
	remotePeer := reqCtx.PeerID

	// Check revocation cache
	if n.revokedPeers != nil {
		if _, isRevoked := n.revokedPeers.Get(remotePeer.String()); isRevoked {
			logger.Warnf("[Auth] Peer %s is revoked", remotePeer)
			return fmt.Errorf("peer is revoked")
		}
	}

	n.keysMu.RLock()
	keys := n.trustedKeys
	n.keysMu.RUnlock()

	var authorized bool
	var lastErr error
	for _, pubKey := range keys {
		logger.Infof("[Auth] Trying key: %x", pubKey.Key)
		if err := n.Authorize(biscuitBytes, reqCtx, pubKey.Key); err == nil {
			authorized = true
			break
		} else {
			lastErr = err
		}
	}

	if !authorized {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("authorization failed")
	}

	return nil
}

func (n *SamNode) Authorize(rawToken []byte, req RequestContext, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(pubKey))
	}
	b, err := biscuit.Unmarshal(rawToken)
	if err != nil {
		return fmt.Errorf("invalid biscuit: %w", err)
	}

	var authOpts []biscuit.AuthorizerOption
	if n.BiscuitTimeout > 0 {
		authOpts = append(authOpts, biscuit.WithWorldOptions(datalog.WithMaxDuration(n.BiscuitTimeout)))
	}
	authorizer, err := b.Authorizer(pubKey, authOpts...)
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
	var opType, opName string
	if req.Target == "" {
		// When no explicit target is requested, the operation is scoped to the connection protocol itself,
		// which resides in the "system" namespace.
		opType = api.SystemNamespace
		opName = req.Protocol
	} else {
		opType, opName = api.ParseServiceTarget(req.Target)
	}
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactService,
			IDs:  []biscuit.Term{biscuit.String(opType), biscuit.String(opName)},
		},
	})

	// Inject connection_peer_id fact for replay defense
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactConnectionPeerID,
			IDs:  []biscuit.Term{biscuit.String(req.PeerID.String())},
		},
	})

	// Enforce client_peer_id matches connection_peer_id
	authorizer.AddCheck(api.BaselineReplayCheck)

	// Inject facts from our own identity token to support target matching
	if err := n.injectIdentityFacts(authorizer, pubKey); err != nil {
		return fmt.Errorf("failed to inject target facts: %w", err)
	}

	if n.LocalPolicy != nil {
		for _, p := range n.LocalPolicy.Policies {
			authorizer.AddPolicy(p)
		}
		for _, c := range n.LocalPolicy.Checks {
			authorizer.AddCheck(c)
		}
		for _, r := range n.LocalPolicy.Rules {
			authorizer.AddRule(r)
		}
	}

	// Apply Baseline Policies and Rules
	authorizer.AddCheck(api.BaselineTargetCheck)
	for _, p := range api.BaselinePolicies {
		authorizer.AddPolicy(p)
	}
	for _, r := range api.BaselineRules {
		authorizer.AddRule(r)
	}

	// Apply Dynamic Mesh Policy Rules
	n.MeshPolicyMu.RLock()
	meshRules := n.MeshPolicyRules
	n.MeshPolicyMu.RUnlock()

	for _, r := range meshRules {
		authorizer.AddRule(r)
	}

	err = authorizer.Authorize()
	if err != nil {
		logger.Errorf("Authorizer failure: %v, token: %s", err, b.String())
		logger.Debugf("Authorizer state: %s", authorizer.PrintWorld())
		return err
	}

	var userStr, emailStr, roleStr string

	if facts, _ := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_user", IDs: []biscuit.Term{biscuit.Variable("u")}},
		Body: []biscuit.Predicate{{Name: api.FactUser, IDs: []biscuit.Term{biscuit.Variable("u")}}},
	}); len(facts) > 0 && len(facts[0].IDs) > 0 {
		if s, ok := facts[0].IDs[0].(biscuit.String); ok {
			userStr = string(s)
		}
	}

	if facts, _ := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_email", IDs: []biscuit.Term{biscuit.Variable("e")}},
		Body: []biscuit.Predicate{{Name: api.FactEmail, IDs: []biscuit.Term{biscuit.Variable("e")}}},
	}); len(facts) > 0 && len(facts[0].IDs) > 0 {
		if s, ok := facts[0].IDs[0].(biscuit.String); ok {
			emailStr = string(s)
		}
	}

	if facts, _ := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_role", IDs: []biscuit.Term{biscuit.Variable("r")}},
		Body: []biscuit.Predicate{{Name: api.FactRole, IDs: []biscuit.Term{biscuit.Variable("r")}}},
	}); len(facts) > 0 && len(facts[0].IDs) > 0 {
		if s, ok := facts[0].IDs[0].(biscuit.String); ok {
			roleStr = string(s)
		}
	}

	logger.Infow("Audit Traceability",
		"peer_id", req.PeerID.String(),
		"user", userStr,
		"email", emailStr,
		"role", roleStr,
		"target", req.Target,
		"protocol", req.Protocol,
	)

	return nil
}

func (n *SamNode) injectIdentityFacts(authorizer biscuit.Authorizer, pubKey ed25519.PublicKey) error {
	ourIdentity := n.GetIdentity()
	if ourIdentity == nil {
		logger.Debugf("[Auth] Node identity is missing, skipping target fact injection")
		return nil
	}

	ourB, err := biscuit.Unmarshal(ourIdentity)
	if err != nil {
		return fmt.Errorf("failed to unmarshal node identity: %w", err)
	}

	n.keysMu.RLock()
	keys := make([]TrustedKey, len(n.trustedKeys))
	copy(keys, n.trustedKeys)
	n.keysMu.RUnlock()

	var auth biscuit.Authorizer
	var authErr error
	for _, tk := range keys {
		if a, err := ourB.Authorizer(tk.Key); err == nil {
			auth = a
			break
		} else {
			authErr = err
		}
	}

	if auth == nil {
		return fmt.Errorf("failed to create authorizer for node identity (signature verification mismatch): %w", authErr)
	}

	// We must Authorize() to evaluate the token's facts into the world
	auth.AddPolicy(api.AllowIfTruePolicy)
	if err := auth.Authorize(); err != nil {
		return fmt.Errorf("failed to validate node identity token (e.g. expired): %w", err)
	}

	for _, rule := range api.TargetFactRules {
		if factSet, err := auth.Query(rule); err == nil {
			for _, fact := range factSet {
				authorizer.AddFact(fact)
			}
		}
	}
	return nil
}
