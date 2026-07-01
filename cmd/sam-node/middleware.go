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
	"crypto/ed25519"
	"fmt"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

var (
	baselinePolicies    []biscuit.Policy
	baselineRules       []biscuit.Rule
	baselineReplayCheck biscuit.Check
	baselineTargetCheck biscuit.Check
	targetFactRules     []biscuit.Rule
)

// init compiles the baseline Datalog rules, policies, and checks for the node.
// These are loaded at initialization to avoid runtime parsing overhead.
func init() {
	// 1. Service Allow Policies
	policyStrs := []string{
		fmt.Sprintf(`allow if service($type, $name), %s($type, $name)`, api.FactGrantedServiceExact),
		fmt.Sprintf(`allow if service($type, $name), %s($type, $prefix), $name.starts_with($prefix)`, api.FactGrantedServicePrefix),
		fmt.Sprintf(`allow if service($type, $name), %s($type, $suffix), $name.ends_with($suffix)`, api.FactGrantedServiceSuffix),
		fmt.Sprintf(`allow if service($type, $name), %s($type)`, api.FactGrantedServiceAll),
		fmt.Sprintf(`allow if service($type, $name), %s()`, api.FactGrantedServiceAllTypes),
		fmt.Sprintf(`allow if service("system", "%s")`, api.CatalogTarget),
	}

	for i, pStr := range policyStrs {
		p, err := parser.FromStringPolicy(pStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline policy %d: %v", i, err))
		}
		baselinePolicies = append(baselinePolicies, p)
	}

	// 2. Target Evaluation Rules
	// These rules satisfy the check if allow_network_target($fact, $val) injected by the Hub.
	ruleStrs := []string{
		fmt.Sprintf(`allow_network_target($fact, $val) <- target_fact($fact, $val), %s($fact, $val)`, api.FactGrantedTargetExact),
		fmt.Sprintf(`allow_network_target($fact, $val) <- target_fact($fact, $val), %s($fact, $prefix), $val.starts_with($prefix)`, api.FactGrantedTargetPrefix),
		fmt.Sprintf(`allow_network_target($fact, $val) <- target_fact($fact, $val), %s($fact, $suffix), $val.ends_with($suffix)`, api.FactGrantedTargetSuffix),
		fmt.Sprintf(`allow_network_target($fact, $val) <- target_fact($fact, $val), %s($fact)`, api.FactGrantedTargetAll),
		fmt.Sprintf(`allow_network_target($fact, $val) <- target_fact($fact, $val), %s()`, api.FactGrantedTargetAllFacts),
	}

	for i, rStr := range ruleStrs {
		r, err := parser.FromStringRule(rStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline rule %d: %v", i, err))
		}
		baselineRules = append(baselineRules, r)
	}

	var err error
	baselineReplayCheck, err = parser.FromStringCheck(`check if client_peer_id($id), connection_peer_id($id)`)
	if err != nil {
		panic(fmt.Sprintf("failed to parse replay check: %v", err))
	}

	baselineTargetCheck, err = parser.FromStringCheck(`check if allow_network_target($fact, $val) or target_unrestricted()`)
	if err != nil {
		panic(fmt.Sprintf("failed to parse target check: %v", err))
	}

	for _, val := range api.OIDCClaimToFact() {
		ruleStr := fmt.Sprintf(`target_fact(%q, $val) <- %s($val)`, val, val)
		r, err := parser.FromStringRule(ruleStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse target fact rule: %v", err))
		}
		targetFactRules = append(targetFactRules, r)
	}

	r, err := parser.FromStringRule(`target_fact("node", $val) <- node($val)`)
	if err != nil {
		panic(fmt.Sprintf("failed to parse node fact rule: %v", err))
	}
	targetFactRules = append(targetFactRules, r)
}

// RequestContext carries the security metadata for a specific stream request
type RequestContext struct {
	PeerID   peer.ID
	User     string
	Group    string
	Protocol string
	Target   string
}

// WithBiscuitAuth enforces a Protobuf handshake on a stream before calling the next handler.
func (n *SamNode) WithBiscuitAuth(next func(network.Stream, RequestContext)) network.StreamHandler {
	return func(s network.Stream) {
		defer func() {
			if err := s.Close(); err != nil {
				logger.Debugf("[Auth] Failed to close stream: %v", err)
			}
		}()
		remotePeer := s.Conn().RemotePeer()

		if !n.rateLimiter.Allow(remotePeer.String()) {
			logger.Warnf("[Auth] Rate limit exceeded for %s, dropping connection", remotePeer)
			_ = s.Reset()
			return
		}

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
		reqCtx := RequestContext{
			PeerID:   remotePeer,
			User:     "", // Not used in Authorize
			Protocol: string(s.Protocol()),
			Target:   authFrame.TargetService,
		}

		writer := msgio.NewVarintWriter(s)

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

		next(s, reqCtx)
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
			Name: "service",
			IDs:  []biscuit.Term{biscuit.String(opType), biscuit.String(opName)},
		},
	})

	// Inject connection_peer_id fact for replay defense
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "connection_peer_id",
			IDs:  []biscuit.Term{biscuit.String(req.PeerID.String())},
		},
	})

	// Enforce client_peer_id matches connection_peer_id
	authorizer.AddCheck(baselineReplayCheck)

	// Inject facts from our own identity token to support target matching
	n.injectIdentityFacts(authorizer, pubKey)

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
	authorizer.AddCheck(baselineTargetCheck)
	for _, p := range baselinePolicies {
		authorizer.AddPolicy(p)
	}
	for _, r := range baselineRules {
		authorizer.AddRule(r)
	}

	err = authorizer.Authorize()
	if err != nil {
		logger.Errorf("Authorizer failure: %v, token: %s", err, b.String())
		logger.Debugf("Authorizer state: %s", authorizer.PrintWorld())
	}
	return err
}

func (n *SamNode) injectIdentityFacts(authorizer biscuit.Authorizer, pubKey ed25519.PublicKey) {
	ourIdentity := n.GetIdentity()
	if ourIdentity == nil {
		return
	}

	ourB, err := biscuit.Unmarshal(ourIdentity)
	if err != nil {
		logger.Warnf("Failed to unmarshal our own identity: %v", err)
		return
	}

	n.keysMu.RLock()
	keys := n.trustedKeys
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
		logger.Warnf("Failed to create authorizer for our own identity: %v", authErr)
		return
	}

	// We must Authorize() to evaluate the token's facts into the world
	if err := auth.Authorize(); err != nil {
		logger.Warnf("Failed to authorize our own identity token: %v", err)
		// we continue anyway, as we just want the facts, but ideally it shouldn't fail
	}

	for _, rule := range targetFactRules {
		if factSet, err := auth.Query(rule); err == nil {
			for _, fact := range factSet {
				authorizer.AddFact(fact)
			}
		}
	}
}
