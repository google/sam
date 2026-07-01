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
	"github.com/google/sam/internal/announce"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"google.golang.org/protobuf/proto"
)

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
		ann := announce.Build(info, n.Host.ID(), addrs, now, announce.TTL)
		if err := announce.Sign(priv, ann); err != nil {
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
