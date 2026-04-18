package protocol

import (
	"context"
	"fmt"
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
