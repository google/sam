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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

type HubSyncMessage struct {
	Action    string   `json:"action"` // ADD, REMOVE, FULL_SYNC
	PeerID    string   `json:"peer_id,omitempty"`
	Peers     []string `json:"peers,omitempty"`
	HubAddrs  []string `json:"hub_addrs,omitempty"`
	Timestamp int64    `json:"timestamp"`
}

func (h *Hub) encryptMsg(plaintext []byte) ([]byte, error) {
	key := sha256.Sum256(h.KeyRing.GetCurrentKey())
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (h *Hub) decryptMsg(ciphertext []byte) ([]byte, error) {
	// Try all valid keys in case a rotation just happened
	for _, priv := range h.KeyRing.GetAllValidKeys() {
		key := sha256.Sum256(priv)
		block, err := aes.NewCipher(key[:])
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			continue
		}
		nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
		if err == nil {
			return plaintext, nil
		}
	}
	return nil, fmt.Errorf("failed to decrypt sync message")
}

func (h *Hub) startSyncListener(ctx context.Context) {
	sub, err := h.SyncTopic.Subscribe()
	if err != nil {
		logger.Errorf("Failed to subscribe to sync topic: %v", err)
		return
	}

	// Message processor
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			if msg.ReceivedFrom == h.Host.ID() {
				continue // Skip our own broadcast
			}

			plaintext, err := h.decryptMsg(msg.Data)
			if err != nil {
				continue // Invalid encryption/key, ignore
			}
			var syncMsg HubSyncMessage
			if err := json.Unmarshal(plaintext, &syncMsg); err != nil {
				continue
			}

			h.gater.mu.Lock()
			switch syncMsg.Action {
			case "ADD":
				p, err := peer.Decode(syncMsg.PeerID)
				if err == nil && !h.gater.authenticated[p] {
					samHubActiveNodes.Inc()
					h.gater.authenticated[p] = true
				}
			case "REMOVE":
				p, err := peer.Decode(syncMsg.PeerID)
				if err == nil && h.gater.authenticated[p] {
					samHubActiveNodes.Dec()
					delete(h.gater.authenticated, p)
				}
			case "FULL_SYNC":
				for _, pStr := range syncMsg.Peers {
					p, err := peer.Decode(pStr)
					if err == nil && !h.gater.authenticated[p] {
						samHubActiveNodes.Inc()
						h.gater.authenticated[p] = true
					}
				}
				if syncMsg.PeerID != "" && len(syncMsg.HubAddrs) > 0 {
					p, err := peer.Decode(syncMsg.PeerID)
					if err == nil {
						h.otherHubAddrs[p] = syncMsg.HubAddrs
					}
				}
			}
			h.gater.mu.Unlock()
		}
	}()

	// Periodic synchronizer
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.publishFullSync(ctx)
			}
		}
	}()

	// Immediate sync broadcast upon starting
	h.publishFullSync(ctx)
}

func (h *Hub) publishFullSync(ctx context.Context) {
	h.gater.mu.RLock()
	var peers []string
	for p := range h.gater.authenticated {
		peers = append(peers, p.String())
	}
	h.gater.mu.RUnlock()

	msg := HubSyncMessage{
		Action:    "FULL_SYNC",
		PeerID:    h.Host.ID().String(),
		Peers:     peers,
		HubAddrs:  h.getMyHubAddrs(),
		Timestamp: time.Now().Unix(),
	}
	h.publishSyncMessage(ctx, msg)
}

func (h *Hub) publishSyncMessage(ctx context.Context, msg HubSyncMessage) {
	data, _ := json.Marshal(msg)
	ciphertext, err := h.encryptMsg(data)
	if err != nil {
		logger.Errorf("Failed to encrypt sync msg: %v", err)
		return
	}
	_ = h.SyncTopic.Publish(ctx, ciphertext)
}

func (h *Hub) getMyHubAddrs() []string {
	var hubAddrs []string
	if len(h.ExternalAddrs) > 0 {
		for _, addr := range h.ExternalAddrs {
			fullAddr := addr
			if !strings.Contains(addr, "/p2p/") {
				fullAddr = addr + "/p2p/" + h.Host.ID().String()
			}
			hubAddrs = append(hubAddrs, fullAddr)
		}
	} else {
		for _, addr := range h.Host.Addrs() {
			if !h.AllowLoopback && isLoopbackOrLinkLocal(addr) {
				continue
			}
			hubAddrs = append(hubAddrs, addr.String()+"/p2p/"+h.Host.ID().String())
		}
	}
	return hubAddrs
}
