package db

import (
	"context"
	"time"
)

const (
	BucketIdentities = "identities"
	BucketVouches    = "vouches"
	BucketReputation = "reputation"
	BucketCache      = "cache"
)

var requiredBuckets = []string{
	BucketIdentities,
	BucketVouches,
	BucketReputation,
	BucketCache,
}

// Metadata is attached to every versioned blob persisted in the store.
type Metadata struct {
	Version int       `json:"version"`
	Updated time.Time `json:"updated_at"`
}

// Store is the unified persistence interface used by SAM subsystems.
// Every mutation and lookup requires a context so callers can enforce
// deadlines and propagate cancellation.
type Store interface {
	Get(ctx context.Context, bucket, key string) ([]byte, error)
	Put(ctx context.Context, bucket, key string, value []byte) error
	Delete(ctx context.Context, bucket, key string) error
	Close() error
}
