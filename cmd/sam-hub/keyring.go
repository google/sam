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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// KeyPair holds an ed25519 keypair and its expiration time if it is a previous key.
type KeyPair struct {
	Private    []byte    `json:"private"`
	Public     []byte    `json:"public"`
	Expiration time.Time `json:"expiration"`
}

// KeyRing manages the active and expired keys for the Hub.
type KeyRing struct {
	Current  KeyPair   `json:"current"`
	Previous []KeyPair `json:"previous"`
	mu       sync.RWMutex
	db       *bbolt.DB
}

// NewKeyRing opens or creates a BoltDB file to store the keyring.
func NewKeyRing(dbPath string, gracePeriod time.Duration, initialSeed []byte) (*KeyRing, error) {
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	kr := &KeyRing{db: db}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("keyring"))
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	if err := kr.load(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to load keyring: %w", err)
	}

	if len(initialSeed) > 0 {
		if len(initialSeed) != ed25519.SeedSize {
			_ = db.Close()
			return nil, fmt.Errorf("invalid seed size: %d, expected %d", len(initialSeed), ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(initialSeed)
		pub := priv.Public().(ed25519.PublicKey)
		
		if !bytes.Equal(kr.Current.Private, priv) {
			if len(kr.Current.Private) > 0 {
				kr.Current.Expiration = time.Now().Add(gracePeriod)
				kr.Previous = append(kr.Previous, kr.Current)
			}
			kr.Current = KeyPair{
				Private: priv,
				Public:  pub,
			}
			if err := kr.save(); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("failed to save initial key: %w", err)
			}
		}
	} else if len(kr.Current.Private) == 0 {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to generate initial key: %w", err)
		}
		kr.Current = KeyPair{
			Private: priv,
			Public:  pub,
		}
		if err := kr.save(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to save initial key: %w", err)
		}
	}

	return kr, nil
}

func (kr *KeyRing) load() error {
	return kr.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("keyring"))
		data := b.Get([]byte("data"))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, kr)
	})
}

func (kr *KeyRing) save() error {
	data, err := json.Marshal(kr)
	if err != nil {
		return err
	}
	return kr.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("keyring"))
		return b.Put([]byte("data"), data)
	})
}

// PrepareRotation generates a new keypair and returns it along with the old private key for signing.
// It does NOT update the current key in the keyring yet.
func (kr *KeyRing) PrepareRotation() (newPub ed25519.PublicKey, newPriv ed25519.PrivateKey, oldPriv ed25519.PrivateKey, err error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	oldPriv = ed25519.PrivateKey(kr.Current.Private)
	newPub, newPriv, err = ed25519.GenerateKey(rand.Reader)
	return newPub, newPriv, oldPriv, err
}

// CommitRotation promotes the new key to current and moves the old current to previous.
func (kr *KeyRing) CommitRotation(newPub ed25519.PublicKey, newPriv ed25519.PrivateKey, gracePeriod time.Duration) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if len(kr.Current.Private) > 0 {
		kr.Current.Expiration = time.Now().Add(gracePeriod)
		kr.Previous = append(kr.Previous, kr.Current)
	}

	kr.Current = KeyPair{
		Private: newPriv,
		Public:  newPub,
	}

	// Clean up expired keys
	now := time.Now()
	var activePrevious []KeyPair
	for _, kp := range kr.Previous {
		if kp.Expiration.After(now) {
			activePrevious = append(activePrevious, kp)
		}
	}
	kr.Previous = activePrevious

	return kr.save()
}

// GetCurrentKey returns the current private key for signing.
func (kr *KeyRing) GetCurrentKey() ed25519.PrivateKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return ed25519.PrivateKey(kr.Current.Private)
}

// GetCurrentPublicKey returns the current public key.
func (kr *KeyRing) GetCurrentPublicKey() ed25519.PublicKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return ed25519.PublicKey(kr.Current.Public)
}

// GetAllValidKeys returns all private keys that are still valid (current + non-expired previous).
func (kr *KeyRing) GetAllValidKeys() []ed25519.PrivateKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	keys := []ed25519.PrivateKey{ed25519.PrivateKey(kr.Current.Private)}
	for _, kp := range kr.Previous {
		keys = append(keys, ed25519.PrivateKey(kp.Private))
	}
	return keys
}

// GetAllValidPublicKeys returns all public keys that are still valid.
func (kr *KeyRing) GetAllValidPublicKeys() []ed25519.PublicKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	keys := []ed25519.PublicKey{ed25519.PublicKey(kr.Current.Public)}
	for _, kp := range kr.Previous {
		keys = append(keys, ed25519.PublicKey(kp.Public))
	}
	return keys
}

// Close closes the BoltDB database.
func (kr *KeyRing) Close() error {
	return kr.db.Close()
}
