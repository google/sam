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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

// DefaultStatePath returns ~/.config/sam/state.db.
func DefaultStatePath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving user config dir: %w", err)
	}
	return filepath.Join(cfgDir, "sam", "state.db"), nil
}

type BoltStore struct {
	db *bbolt.DB
}

// OpenDefault opens the default bbolt state DB and initializes required buckets.
func OpenDefault() (*BoltStore, error) {
	path, err := DefaultStatePath()
	if err != nil {
		return nil, err
	}
	return Open(path)
}

// Open opens a bbolt store at the given path and initializes required buckets.
func Open(path string) (*BoltStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening bbolt store: %w", err)
	}
	s := &BoltStore{db: db}
	if err := s.initBuckets(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *BoltStore) initBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, bucket := range requiredBuckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return fmt.Errorf("creating bucket %q: %w", bucket, err)
			}
		}
		return nil
	})
}

func (s *BoltStore) Get(ctx context.Context, bucket, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q does not exist", bucket)
		}
		value := b.Get([]byte(key))
		if value == nil {
			return os.ErrNotExist
		}
		out = append([]byte(nil), value...)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("get %s/%s: %w", bucket, key, err)
	}
	return out, nil
}

func (s *BoltStore) Put(ctx context.Context, bucket, key string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(value) == 0 {
		return fmt.Errorf("value is required")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q does not exist", bucket)
		}
		return b.Put([]byte(key), value)
	})
}

func (s *BoltStore) Delete(ctx context.Context, bucket, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q does not exist", bucket)
		}
		return b.Delete([]byte(key))
	})
}

func (s *BoltStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
