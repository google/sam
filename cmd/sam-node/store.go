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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.etcd.io/bbolt"
	bbolterrors "go.etcd.io/bbolt/errors"
)

const (
	bucketIdentity = "identity"
	keyBiscuit     = "identity_biscuit"
	keyPrivKey     = "node_private_key"
	keyIdentityExp = "identity_expiration"
)

type Store struct {
	db *bbolt.DB
}

func GetDefaultDataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "sam-mesh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func NewStore(dir string) (*Store, error) {
	dbPath := filepath.Join(dir, "agent.db")
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		if errors.Is(err, bbolterrors.ErrTimeout) {
			return nil, fmt.Errorf("timeout waiting for file lock, is another instance of sam-node running?")
		}
		return nil, err
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketIdentity)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketBannedPeers)); err != nil {
			return err
		}
		return nil
	})

	return &Store{db: db}, err
}

func (s *Store) SaveIdentity(biscuit []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		return b.Put([]byte(keyBiscuit), biscuit)
	})
}

func (s *Store) LoadIdentity() ([]byte, error) {
	var val []byte
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		val = b.Get([]byte(keyBiscuit))
		return nil
	})
	if len(val) == 0 {
		return nil, fmt.Errorf("no identity found")
	}
	return val, nil
}

func (s *Store) SaveIdentityExpiration(exp int64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		return b.Put([]byte(keyIdentityExp), []byte(fmt.Sprintf("%d", exp)))
	})
}

func (s *Store) LoadIdentityExpiration() (int64, error) {
	var val []byte
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		val = b.Get([]byte(keyIdentityExp))
		return nil
	})
	if len(val) == 0 {
		return 0, fmt.Errorf("no identity expiration found")
	}
	var exp int64
	_, err := fmt.Sscanf(string(val), "%d", &exp)
	if err != nil {
		return 0, err
	}
	return exp, nil
}

func (s *Store) SaveKey(key []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		return b.Put([]byte(keyPrivKey), key)
	})
}

func (s *Store) LoadKey() ([]byte, error) {
	var val []byte
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		val = b.Get([]byte(keyPrivKey))
		return nil
	})
	return val, nil
}

func (s *Store) SaveHubConfig(pubKey []byte, addrs []string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		if err := b.Put([]byte("hub_public_key"), pubKey); err != nil {
			return err
		}
		data, _ := json.Marshal(addrs)
		return b.Put([]byte("hub_addresses"), data)
	})
}

func (s *Store) LoadHubConfig() ([]byte, []string, error) {
	var pubKey []byte
	var addrs []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		pubKey = b.Get([]byte("hub_public_key"))
		addrsBytes := b.Get([]byte("hub_addresses"))
		if len(addrsBytes) > 0 {
			return json.Unmarshal(addrsBytes, &addrs)
		}
		return nil
	})
	return pubKey, addrs, err
}

func (s *Store) SaveHubURL(url string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		return b.Put([]byte("hub_url"), []byte(url))
	})
}

func (s *Store) LoadHubURL() (string, error) {
	var val []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		val = b.Get([]byte("hub_url"))
		return nil
	})
	return string(val), err
}

func (s *Store) Close() error {
	return s.db.Close()
}

const (
	bucketBannedPeers = "banned_peers"
)

// IsBanned checks local store to see if this peer is banned.
func (s *Store) IsBanned(p peer.ID) bool {
	var banned bool
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketBannedPeers))
		if b == nil {
			return nil
		}
		if b.Get([]byte(p.String())) != nil {
			banned = true
		}
		return nil
	})
	return banned
}
