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
	"time"

	"github.com/google/sam/api"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// serviceAnnounceTTL is the lifetime a catalog should keep an entry before
// eviction; ~3x the 5-min reprovide tick so one dropped announce is tolerated.
const serviceAnnounceTTL = 15 * time.Minute

// buildServiceAnnounce assembles an unsigned announce for a local service.
func buildServiceAnnounce(info *api.ServiceInfo, peerID peer.ID, addrs []string, now time.Time, ttl time.Duration) *api.ServiceAnnounce {
	return &api.ServiceAnnounce{
		Type:      info.Type,
		Name:      info.Name,
		PeerId:    peerID.String(),
		Addrs:     addrs,
		Timestamp: now.UnixMilli(),
		TtlMs:     ttl.Milliseconds(),
	}
}

// signServiceAnnounce signs the announce over its signature-cleared marshalling.
func signServiceAnnounce(priv crypto.PrivKey, a *api.ServiceAnnounce) error {
	a.Signature = nil
	data, err := proto.Marshal(a)
	if err != nil {
		return err
	}
	sig, err := priv.Sign(data)
	if err != nil {
		return err
	}
	a.Signature = sig
	return nil
}

// verifyServiceAnnounce checks the signature against the key derived from PeerId.
func verifyServiceAnnounce(a *api.ServiceAnnounce) (bool, error) {
	pid, err := peer.Decode(a.PeerId)
	if err != nil {
		return false, err
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil {
		return false, err
	}
	sig := a.Signature
	a.Signature = nil
	data, err := proto.Marshal(a)
	a.Signature = sig // restore
	if err != nil {
		return false, err
	}
	return pub.Verify(data, sig)
}

// joinTopic returns the cached topic, joining and caching it on first use.
func (n *SamNode) joinTopic(name string) (*pubsub.Topic, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if t, ok := n.topics[name]; ok {
		return t, nil
	}
	t, err := n.PubSub.Join(name)
	if err != nil {
		return nil, err
	}
	n.topics[name] = t
	return t, nil
}

// announceServices publishes a signed ServiceAnnounce for every local service.
func (n *SamNode) announceServices(ctx context.Context) {
	if n.PubSub == nil || n.Host == nil || n.services == nil {
		return
	}
	priv := n.Host.Peerstore().PrivKey(n.Host.ID())
	if priv == nil {
		logger.Warnf("[Announce] no private key for self; skipping announce")
		return
	}

	addrs := make([]string, 0, len(n.Host.Addrs()))
	for _, a := range n.Host.Addrs() {
		addrs = append(addrs, a.String())
	}

	topic, err := n.joinTopic(api.GossipServiceAnnounce)
	if err != nil {
		logger.Warnf("[Announce] join topic: %v", err)
		return
	}

	now := time.Now()
	for _, info := range n.services.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED) {
		ann := buildServiceAnnounce(info, n.Host.ID(), addrs, now, serviceAnnounceTTL)
		if err := signServiceAnnounce(priv, ann); err != nil {
			logger.Warnf("[Announce] sign %s: %v", info.Name, err)
			continue
		}
		data, err := proto.Marshal(ann)
		if err != nil {
			logger.Warnf("[Announce] marshal %s: %v", info.Name, err)
			continue
		}
		if err := topic.Publish(ctx, data); err != nil {
			logger.Warnf("[Announce] publish %s: %v", info.Name, err)
		}
	}
}
