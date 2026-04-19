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

package samnet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"go.etcd.io/bbolt"

	internaldb "sam/internal/db"
)

const (
	agentCacheRecordVersion = 1
	agentCacheCardPrefix    = "agent-card/"
	defaultInformerPeriod   = 2 * time.Second
)

type AgentWatchEventType string

const (
	AgentWatchEventAdded AgentWatchEventType = "ADDED"
)

type AgentWatchEvent struct {
	Type   AgentWatchEventType `json:"type"`
	PeerID string              `json:"peer_id,omitempty"`
	Card   json.RawMessage     `json:"card,omitempty"`
}

type DiscoveredAgent struct {
	PeerID       string
	Card         []byte
	Capabilities []string
}

type AgentDiscoverFunc func(context.Context) ([]DiscoveredAgent, error)

type LocalInformer struct {
	node       Node
	federation string
	interval   time.Duration
	emitter    event.Emitter
	discover   AgentDiscoverFunc

	mu        sync.Mutex
	knownByID map[string]string
}

type LocalInformerOption func(*LocalInformer)

func WithInformerInterval(interval time.Duration) LocalInformerOption {
	return func(informer *LocalInformer) {
		informer.interval = interval
	}
}

func WithInformerDiscoverer(discover AgentDiscoverFunc) LocalInformerOption {
	return func(informer *LocalInformer) {
		informer.discover = discover
	}
}

func NewLocalInformer(node Node, federation string, opts ...LocalInformerOption) (*LocalInformer, error) {
	if node == nil || node.Host() == nil {
		return nil, fmt.Errorf("node host is required")
	}
	emitter, err := node.Host().EventBus().Emitter(new(AgentWatchEvent))
	if err != nil {
		return nil, fmt.Errorf("creating agent event emitter: %w", err)
	}
	informer := &LocalInformer{
		node:       node,
		federation: strings.TrimSpace(federation),
		interval:   defaultInformerPeriod,
		emitter:    emitter,
		knownByID:  map[string]string{},
	}
	for _, opt := range opts {
		opt(informer)
	}
	if informer.interval <= 0 {
		informer.interval = defaultInformerPeriod
	}
	if informer.discover == nil {
		return nil, fmt.Errorf("informer discoverer is required")
	}
	cached, err := LoadCachedAgentRecords(informer.federation)
	if err != nil {
		return nil, err
	}
	for _, record := range cached {
		if strings.TrimSpace(record.PeerID) == "" {
			continue
		}
		informer.knownByID[record.PeerID] = informer.fingerprint(record.PeerID, record.Card)
	}
	return informer, nil
}

func (i *LocalInformer) Start(ctx context.Context) {
	go func() {
		_ = i.Sync(ctx)
		ticker := time.NewTicker(i.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = i.Sync(ctx)
			}
		}
	}()
}

func (i *LocalInformer) Sync(ctx context.Context) error {
	records, err := i.discover(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := UpsertCachedAgentRecord(i.federation, record); err != nil {
			continue
		}
		if i.markSeen(record) {
			_ = i.emitter.Emit(AgentWatchEvent{Type: AgentWatchEventAdded, PeerID: record.PeerID, Card: append([]byte(nil), record.Card...)})
		}
	}
	return nil
}

func (i *LocalInformer) markSeen(record DiscoveredAgent) bool {
	fingerprint := i.fingerprint(record.PeerID, record.Card)
	i.mu.Lock()
	defer i.mu.Unlock()
	if known, ok := i.knownByID[record.PeerID]; ok && known == fingerprint {
		return false
	}
	i.knownByID[record.PeerID] = fingerprint
	return true
}

func (i *LocalInformer) fingerprint(peerID string, card []byte) string {
	return strings.TrimSpace(peerID) + "|" + string(card)
}

type CachedAgentRecord struct {
	PeerID       string          `json:"peer_id"`
	Card         json.RawMessage `json:"card"`
	Capabilities []string        `json:"capabilities,omitempty"`
}

func LoadCachedAgentRecords(federation string) ([]CachedAgentRecord, error) {
	path, err := federationDBPath(federation)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	codec := internaldb.JSONCodec{}
	seen := map[string]struct{}{}
	out := make([]CachedAgentRecord, 0)
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(internaldb.BucketCache))
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(key, value []byte) error {
			if !strings.HasPrefix(string(key), agentCacheCardPrefix) {
				return nil
			}
			var record CachedAgentRecord
			if err := codec.Unmarshal(value, agentCacheRecordVersion, &record, nil); err != nil {
				return nil
			}
			if strings.TrimSpace(record.PeerID) == "" {
				return nil
			}
			if _, ok := seen[record.PeerID]; ok {
				return nil
			}
			seen[record.PeerID] = struct{}{}
			out = append(out, record)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func CachedCapabilities(federation string) ([]string, error) {
	records, err := LoadCachedAgentRecords(federation)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, record := range records {
		for _, capability := range record.Capabilities {
			capability = strings.TrimSpace(capability)
			if capability == "" {
				continue
			}
			if _, ok := seen[capability]; ok {
				continue
			}
			seen[capability] = struct{}{}
			out = append(out, capability)
		}
	}
	return out, nil
}

func UpsertCachedAgentRecord(federation string, record DiscoveredAgent) error {
	if strings.TrimSpace(record.PeerID) == "" || len(record.Card) == 0 {
		return nil
	}
	path, err := federationDBPath(federation)
	if err != nil {
		return err
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	codec := internaldb.JSONCodec{}
	payload, err := codec.Marshal(agentCacheRecordVersion, CachedAgentRecord{
		PeerID:       record.PeerID,
		Card:         append([]byte(nil), record.Card...),
		Capabilities: append([]string(nil), record.Capabilities...),
	})
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(internaldb.BucketCache))
		if err != nil {
			return fmt.Errorf("ensuring cache bucket: %w", err)
		}
		return bucket.Put([]byte(agentCacheCardPrefix+record.PeerID), payload)
	})
}

func federationDBPath(federation string) (string, error) {
	baseDir, err := internaldb.FederationsDir()
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(federation)
	if name == "" {
		name = "default"
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(baseDir, name+".db"), nil
}
