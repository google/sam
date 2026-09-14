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

package discovery

import (
	"context"
	"time"

	"github.com/google/sam/api"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// Ensure registers interest in a routing key: it subscribes to the key's
// topic (if not already) and refreshes the interest TTL. Safe to call on
// every request for the key.
func (d *Discovery) Ensure(t api.ServiceType, key string) {
	name, err := api.DiscoveryTopic(t, key)
	if err != nil {
		return
	}
	d.viewMu.Lock()
	defer d.viewMu.Unlock()
	if in, ok := d.interests[name]; ok {
		in.expires = time.Now().Add(d.interestTTL)
		return
	}
	topic, release, err := d.tm.acquire(name)
	if err != nil {
		logger.Warnf("[Discovery] join %s: %v", name, err)
		return
	}
	sub, err := topic.Subscribe()
	if err != nil {
		release()
		logger.Warnf("[Discovery] subscribe %s: %v", name, err)
		return
	}
	d.interests[name] = &interest{
		sub:     sub,
		release: release,
		expires: time.Now().Add(d.interestTTL),
	}
	ctx := d.runCtx
	if ctx == nil {
		ctx = context.Background()
	}
	go d.readLoop(ctx, sub)
}

// Providers returns the fresh, non-self providers observed for a key.
func (d *Discovery) Providers(t api.ServiceType, key string) []Provider {
	d.viewMu.Lock()
	defer d.viewMu.Unlock()
	cutoff := time.Now().Add(-d.staleAfter)
	var out []Provider
	for _, p := range d.providers {
		if p.Type == t && p.LastSeen.After(cutoff) && p.ServesKey(key) {
			out = append(out, p)
		}
	}
	return out
}

// PeerLabels returns the labels last observed for a peer, if any. Labels are
// node-level claims (e.g. region), so any fresh entry of the peer suffices.
func (d *Discovery) PeerLabels(peerID string) map[string]string {
	d.viewMu.Lock()
	defer d.viewMu.Unlock()
	cutoff := time.Now().Add(-d.staleAfter)
	for _, p := range d.providers {
		if p.PeerID == peerID && p.LastSeen.After(cutoff) && len(p.Labels) > 0 {
			return p.Labels
		}
	}
	return nil
}

// readLoop consumes one subscription until it is cancelled or ctx ends.
func (d *Discovery) readLoop(ctx context.Context, sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return // subscription cancelled or ctx done
		}
		if msg.GetFrom() == d.self {
			continue
		}
		d.observe(msg)
	}
}

// observe validates a gossiped announcement and records the provider.
func (d *Discovery) observe(msg *pubsub.Message) {
	var ann api.ServiceAnnounce
	if err := proto.Unmarshal(msg.Data, &ann); err != nil {
		logger.Debugf("[Discovery] dropping undecodable announce from %s: %v", msg.GetFrom(), err)
		return
	}
	if err := api.ValidateServiceAnnounce(&ann); err != nil {
		logger.Debugf("[Discovery] dropping invalid announce from %s: %v", msg.GetFrom(), err)
		return
	}
	// The claimed identity must be the pubsub message signer.
	claimed, err := peer.Decode(ann.GetPeerId())
	if err != nil || claimed != msg.GetFrom() {
		logger.Warnf("[Discovery] dropping announce with peer_id %q not matching signer %s", ann.GetPeerId(), msg.GetFrom())
		return
	}
	ts := time.Unix(ann.GetTimestamp(), 0)
	if age := time.Since(ts); age > maxAnnounceSkew || age < -maxAnnounceSkew {
		logger.Debugf("[Discovery] dropping stale/future announce from %s (age %v)", msg.GetFrom(), time.Since(ts))
		return
	}

	// claimed, not ann.GetPeerId(): a peer ID has several valid encodings that
	// all decode to the same peer -- base58, and CIDv1 in base32/base36/base58btc
	// -- so the announced string passes the signer check above whichever one it
	// used. Everything downstream compares this value against a canonical
	// peer.ID.String(): the revocation cache is keyed that way, and PeerLabels
	// matches on equality. Storing the announced spelling would leave those
	// lookups missing a peer that is present, and would let one peer hold two
	// entries under two spellings.
	canonicalID := claimed.String()

	typeStr, _ := api.ServiceTypeToString(ann.GetType())
	entryKey := canonicalID + "|" + typeStr + "|" + ann.GetServiceName()

	d.viewMu.Lock()
	defer d.viewMu.Unlock()
	if _, exists := d.providers[entryKey]; !exists && len(d.providers) >= d.maxProviders {
		d.evictOldestLocked()
	}
	d.providers[entryKey] = Provider{
		PeerID:  canonicalID,
		Type:    ann.GetType(),
		Service: ann.GetServiceName(),
		Keys:    ann.GetKeys(),
		Labels:  ann.GetLabels(),
		Load: Load{
			ActiveRequests: ann.GetActiveRequests(),
			LatencyEWMAMs:  ann.GetLatencyEwmaMs(),
		},
		LastSeen: time.Now(),
	}
}

func (d *Discovery) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, p := range d.providers {
		if oldestKey == "" || p.LastSeen.Before(oldest) {
			oldestKey, oldest = k, p.LastSeen
		}
	}
	if oldestKey != "" {
		delete(d.providers, oldestKey)
	}
}

// janitorLoop drops expired interests and stale provider entries.
func (d *Discovery) janitorLoop(ctx context.Context) {
	ticker := time.NewTicker(d.interestTTL / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.viewMu.Lock()
			for name, in := range d.interests {
				in.sub.Cancel()
				in.release()
				delete(d.interests, name)
			}
			d.viewMu.Unlock()
			return
		case <-ticker.C:
			now := time.Now()
			d.viewMu.Lock()
			for name, in := range d.interests {
				if now.After(in.expires) {
					in.sub.Cancel()
					in.release()
					delete(d.interests, name)
				}
			}
			cutoff := now.Add(-2 * d.staleAfter)
			for k, p := range d.providers {
				if p.LastSeen.Before(cutoff) {
					delete(d.providers, k)
				}
			}
			d.viewMu.Unlock()
		}
	}
}
