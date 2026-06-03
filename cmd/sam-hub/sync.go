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
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

func (h *Hub) encryptMsg(plaintext []byte) ([]byte, error) {
	if len(h.SyncKey) == 0 {
		return nil, fmt.Errorf("no sync key available")
	}
	key := sha256.Sum256(h.SyncKey)
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
	if len(h.SyncKey) == 0 {
		return nil, fmt.Errorf("no sync key available")
	}
	key := sha256.Sum256(h.SyncKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, actualCiphertext, nil)
}

func (h *Hub) startSyncListener(ctx context.Context) {
	if h.SyncTopic == nil {
		logger.Warn("SyncTopic is nil, sync listener will not start")
		return
	}
	sub, err := h.SyncTopic.Subscribe()
	if err != nil {
		logger.Errorf("Failed to subscribe to sync topic: %v", err)
		return
	}

	// Message processor
	go func() {
		defer sub.Cancel()
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			fromPeer, err := peer.IDFromBytes(msg.From)
			if err == nil && fromPeer == h.Host.ID() {
				continue // Skip our own broadcast
			}

			plaintext, err := h.decryptMsg(msg.Data)
			if err != nil {
				continue // Invalid encryption/key, ignore
			}
			var syncMsg api.HubSyncMessage
			if err := proto.Unmarshal(plaintext, &syncMsg); err != nil {
				continue
			}

			h.gater.mu.Lock()
			switch syncMsg.Action {
			case api.HubSyncMessage_ADD:
				p, err := peer.Decode(syncMsg.PeerId)
				if err == nil {
					if syncMsg.Timestamp > h.gater.lastUpdated[p] {
						h.gater.lastUpdated[p] = syncMsg.Timestamp
						if !h.gater.authenticated[p] {
							samHubActiveNodes.Inc()
							h.gater.authenticated[p] = true
						}
					}
				}
			case api.HubSyncMessage_REMOVE:
				p, err := peer.Decode(syncMsg.PeerId)
				if err == nil {
					if syncMsg.Timestamp > h.gater.lastUpdated[p] {
						h.gater.lastUpdated[p] = syncMsg.Timestamp
						if h.gater.authenticated[p] {
							samHubActiveNodes.Dec()
							delete(h.gater.authenticated, p)
						}
					}
				}
			case api.HubSyncMessage_FULL_SYNC:
				activePeers := make(map[string]bool)
				for _, activeStr := range syncMsg.Peers {
					activePeers[activeStr] = true
				}

				for pStr, ts := range syncMsg.PeerTimestamps {
					p, err := peer.Decode(pStr)
					if err != nil {
						continue
					}
					if ts > h.gater.lastUpdated[p] {
						h.gater.lastUpdated[p] = ts

						// Determine if the peer is active in the incoming state
						if activePeers[pStr] {
							if !h.gater.authenticated[p] {
								samHubActiveNodes.Inc()
								h.gater.authenticated[p] = true
							}
						} else {
							if h.gater.authenticated[p] {
								samHubActiveNodes.Dec()
								delete(h.gater.authenticated, p)
							}
						}
					}
				}
				if syncMsg.PeerId != "" && len(syncMsg.HubAddrs) > 0 {
					p, err := peer.Decode(syncMsg.PeerId)
					if err == nil {
						h.otherHubAddrs[p] = syncMsg.HubAddrs
						h.otherHubLastSeen[p] = time.Now()
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
				h.pruneStaleData()
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
	peerTimestamps := make(map[string]int64)
	for p, ts := range h.gater.lastUpdated {
		peerTimestamps[p.String()] = ts
	}
	h.gater.mu.RUnlock()

	msg := api.HubSyncMessage{
		Action:         api.HubSyncMessage_FULL_SYNC,
		PeerId:         h.Host.ID().String(),
		Peers:          peers,
		HubAddrs:       h.getMyHubAddrs(),
		Timestamp:      time.Now().UnixMilli(),
		PeerTimestamps: peerTimestamps,
	}
	h.publishSyncMessage(ctx, &msg)
}

func (h *Hub) publishSyncMessage(ctx context.Context, msg *api.HubSyncMessage) {
	if h.SyncTopic == nil {
		logger.Warn("SyncTopic is nil, sync message will not be published")
		return
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		logger.Errorf("Failed to marshal sync msg: %v", err)
		return
	}
	ciphertext, err := h.encryptMsg(data)
	if err != nil {
		logger.Errorf("Failed to encrypt sync msg: %v", err)
		return
	}
	if err := h.SyncTopic.Publish(ctx, ciphertext); err != nil {
		logger.Errorf("Failed to publish sync msg: %v", err)
	}
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

func (h *Hub) pruneStaleData() {
	h.gater.mu.Lock()
	defer h.gater.mu.Unlock()
	now := time.Now()
	for p, lastSeen := range h.otherHubLastSeen {
		if now.Sub(lastSeen) > 45*time.Second {
			delete(h.otherHubAddrs, p)
			delete(h.otherHubLastSeen, p)
			logger.Infof("Pruned stale hub %s (last seen %s ago)", p.String(), now.Sub(lastSeen))
		}
	}

	nowMilli := now.UnixMilli()
	for p, ts := range h.gater.lastUpdated {
		if !h.gater.authenticated[p] {
            if nowMilli-ts > int64(time.Hour/time.Millisecond) {
				delete(h.gater.lastUpdated, p)
				logger.Debugf("Pruned transient peer %s from lastUpdated", p.String())
			}
		}
	}
}
