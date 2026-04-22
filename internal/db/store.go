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

package db

import (
	"context"
	"time"
)

const (
	BucketIdentities = "identities"
	BucketReputation = "reputation"
	BucketCache      = "cache"
)

var requiredBuckets = []string{
	BucketIdentities,
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
