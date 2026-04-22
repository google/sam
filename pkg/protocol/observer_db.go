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

package protocol

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	internaldb "sam/internal/db"
)

const reputationRecordVersion = 1

type reputationRecord struct {
	PeerID    string `json:"peer_id"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	ErrorType string `json:"error_type,omitempty"`
}

// BoltObserver persists A2A success/failure events for local reputation tracking.
type BoltObserver struct {
	mu    sync.Mutex
	store internaldb.Store
	codec internaldb.Codec
}

// DefaultBoltObserver opens ~/.config/sam/state.db.
func DefaultBoltObserver() (*BoltObserver, error) {
	store, err := internaldb.OpenDefault()
	if err != nil {
		return nil, fmt.Errorf("opening default state store: %w", err)
	}
	return &BoltObserver{store: store, codec: internaldb.JSONCodec{}}, nil
}

// NewBoltObserver opens or creates an observer database at path.
func NewBoltObserver(path string) (*BoltObserver, error) {
	store, err := internaldb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening state store: %w", err)
	}
	return &BoltObserver{store: store, codec: internaldb.JSONCodec{}}, nil
}

// NewBoltObserverForFederation opens a reputation observer scoped to the given
// federation name. The database is stored at
// ~/.config/sam/federations/<name>.db.
func NewBoltObserverForFederation(fedID string) (*BoltObserver, error) {
	fedID = strings.TrimSpace(fedID)
	if fedID == "" {
		fedID = "default"
	}
	mgr, err := internaldb.NewManager()
	if err != nil {
		return nil, fmt.Errorf("creating federation manager: %w", err)
	}
	store, err := mgr.Store(fedID)
	if err != nil {
		_ = mgr.Close()
		return nil, fmt.Errorf("opening federation %q store: %w", fedID, err)
	}
	return &BoltObserver{store: store, codec: internaldb.JSONCodec{}}, nil
}

// NewBoltObserverWithFallback prefers federation-scoped storage and falls back
// to default state storage when federation manager setup is unavailable.
func NewBoltObserverWithFallback(fedID string) (*BoltObserver, error) {
	observer, err := NewBoltObserverForFederation(fedID)
	if err == nil {
		return observer, nil
	}
	fallback, fallbackErr := DefaultBoltObserver()
	if fallbackErr != nil {
		return nil, fmt.Errorf("creating federation observer: %v; fallback failed: %w", err, fallbackErr)
	}
	return fallback, nil
}

func (o *BoltObserver) OnSuccess(peerID string, latency time.Duration) {
	o.writeRecord(peerID, reputationRecord{PeerID: peerID, OK: true, LatencyMS: latency.Milliseconds()})
}

func (o *BoltObserver) OnFailure(peerID string, errorType string) {
	o.writeRecord(peerID, reputationRecord{PeerID: peerID, OK: false, ErrorType: errorType})
}

func (o *BoltObserver) writeRecord(peerID string, rec reputationRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := fmt.Sprintf("%s/%020d", peerID, time.Now().UTC().UnixNano())
	encoded, err := o.codec.Marshal(reputationRecordVersion, rec)
	if err != nil {
		return
	}
	_ = o.store.Put(context.Background(), internaldb.BucketReputation, key, encoded)
}

// Close closes the underlying store handle.
func (o *BoltObserver) Close() error {
	if o == nil || o.store == nil {
		return nil
	}
	return o.store.Close()
}
