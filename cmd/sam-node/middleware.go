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
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
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
			Protocol: s.Protocol(),
		}

		writer := msgio.NewVarintWriter(s)

		// Check revocation cache
		if _, isRevoked := n.revokedPeers.Get(remotePeer.String()); isRevoked {
			logger.Warnf("[Auth] Peer %s is revoked", remotePeer)
			resp := &api.AuthResponse{Success: false, Error: "Peer is revoked"}
			respBytes, err := proto.Marshal(resp)
			if err != nil {
				logger.Errorf("[Auth] Failed to marshal revocation response: %v", err)
				return
			}
			_ = writer.WriteMsg(respBytes)
			return
		}

		// Check verification cache
		tokenHash := sha256.Sum256(authFrame.Biscuit)
		hashStr := hex.EncodeToString(tokenHash[:]) + ":" + remotePeer.String()

		if pubKeyStr, ok := n.verificationCache.Get(hashStr); ok {
			n.keysMu.RLock()
			keys := n.trustedKeys
			n.keysMu.RUnlock()

			trusted := false
			for _, tk := range keys {
				if hex.EncodeToString(tk.Key) == pubKeyStr {
					trusted = true
					break
				}
			}
			if trusted {
				logger.Infof("[Auth] Token cache hit for %s", remotePeer)
				// Valid
				resp := &api.AuthResponse{Success: true}
				respBytes, err := proto.Marshal(resp)
				if err != nil {
					logger.Errorf("[Auth] Failed to marshal ACK response: %v", err)
					return
				}
				if err := writer.WriteMsg(respBytes); err != nil {
					logger.Errorf("[Auth] Failed to write ACK to %s: %v", remotePeer, err)
					return
				}
				next(s)
				return
			}
		}

		n.keysMu.RLock()
		keys := n.trustedKeys
		n.keysMu.RUnlock()

		var authorized bool
		var lastErr error
		var successfulKey ed25519.PublicKey
		for _, pubKey := range keys {
			logger.Infof("[Auth] Trying key: %x", pubKey.Key)
			if err := n.Authorize(authFrame.Biscuit, reqCtx, pubKey.Key); err == nil {
				authorized = true
				successfulKey = pubKey.Key
				break
			} else {
				lastErr = err
			}
		}

		if !authorized {
			logger.Infof("[Auth] All keys failed, triggering re-enrollment fallback for %s", remotePeer)
			var jwtStr string
			var err error

			if oidcIssuerFlag != "" {
				tokenURL, err := n.DiscoverTokenURL(context.Background(), oidcIssuerFlag)
				if err != nil {
					logger.Errorf("[Auth] Failed to discover OIDC endpoints for fallback: %v", err)
				} else {
					jwtStr, err = n.FetchJWT(context.Background(), tokenURL, clientIDFlag, clientSecretFlag)
					if err != nil {
						logger.Errorf("[Auth] Failed to fetch JWT for fallback: %v", err)
					}
				}
			} else if jwtPathFlag != "" {
				data, err := os.ReadFile(jwtPathFlag)
				if err != nil {
					logger.Errorf("[Auth] Failed to read JWT file for fallback: %v", err)
				} else {
					jwtStr = strings.TrimSpace(string(data))
				}
			}

			if jwtStr != "" {
				err = n.Enroll(context.Background(), jwtStr)
				if err != nil {
					logger.Errorf("[Auth] Fallback enrollment failed: %v", err)
				} else {
					// Retry authorization with new keys
					n.keysMu.RLock()
					keys = n.trustedKeys
					n.keysMu.RUnlock()

					for _, pubKey := range keys {
						logger.Infof("[Auth] Retrying with key: %x", pubKey.Key)
						if err := n.Authorize(authFrame.Biscuit, reqCtx, pubKey.Key); err == nil {
							authorized = true
							break
						} else {
							lastErr = err
						}
					}
				}
			}
		}

		if !authorized {
			logger.Warnf("[Auth] AuthZ Denied %s: %v", remotePeer, lastErr)
			resp := &api.AuthResponse{Success: false, Error: "Authorization failed"}
			if lastErr != nil {
				resp.Error = lastErr.Error()
			}
			respBytes, _ := proto.Marshal(resp)
			_ = writer.WriteMsg(respBytes)
			return
		}

		// Cache successful verification
		n.verificationCache.Add(hashStr, hex.EncodeToString(successfulKey))

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

func (n *SamNode) Authorize(rawToken []byte, req RequestContext, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(pubKey))
	}
	b, err := biscuit.Unmarshal(rawToken)
	if err != nil {
		return fmt.Errorf("invalid biscuit: %w", err)
	}

	authorizer, err := b.Authorizer(pubKey)
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

	// Inject connection_peer_id fact for replay defense
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "connection_peer_id",
			IDs:  []biscuit.Term{biscuit.String(req.PeerID.String())},
		},
	})

	// Enforce client_peer_id matches connection_peer_id
	replayCheckStr := `check if client_peer_id($id), connection_peer_id($id)`
	replayCheck, err := parser.FromStringCheck(replayCheckStr)
	if err != nil {
		return fmt.Errorf("failed to parse replay check: %w", err)
	}
	authorizer.AddCheck(replayCheck)

	// Apply Pre-compiled Local Attenuation
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

	// Baseline Rules
	rule1Str := fmt.Sprintf(`allow if operation($op), %s($op)`, api.FactMCPTool)
	rule1, err := parser.FromStringPolicy(rule1Str)
	if err != nil {
		return fmt.Errorf("failed to parse baseline rule 1: %w", err)
	}
	authorizer.AddPolicy(rule1)

	rule2Str := fmt.Sprintf(`allow if operation($op), %s("*")`, api.FactMCPTool)
	rule2, err := parser.FromStringPolicy(rule2Str)
	if err != nil {
		return fmt.Errorf("failed to parse baseline rule 2: %w", err)
	}
	authorizer.AddPolicy(rule2)

	return authorizer.Authorize()
}
