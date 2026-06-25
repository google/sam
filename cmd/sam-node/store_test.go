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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.etcd.io/bbolt"
)

func TestStore_NewStore_And_Close(t *testing.T) {
	tempDir := t.TempDir()

	store, err := NewStore(tempDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	dbPath := filepath.Join(tempDir, "agent.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file does not exist at %s", dbPath)
	}

	if err := store.Close(); err != nil {
		t.Errorf("Failed to close store: %v", err)
	}
}

func TestStore_Identity(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading identity when not set should fail
	_, err = store.LoadIdentity()
	if err == nil {
		t.Error("Expected error loading identity when none is saved, got nil")
	}

	biscuit := []byte("dummy-biscuit-data")
	if err := store.SaveIdentity(biscuit); err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	loaded, err := store.LoadIdentity()
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}

	if !bytes.Equal(loaded, biscuit) {
		t.Errorf("Expected loaded identity %s, got %s", string(biscuit), string(loaded))
	}
}

func TestStore_IdentityExpiration(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set should fail
	_, err = store.LoadIdentityExpiration()
	if err == nil {
		t.Error("Expected error loading identity expiration when none is saved, got nil")
	}

	exp := int64(1782418067)
	if err := store.SaveIdentityExpiration(exp); err != nil {
		t.Fatalf("SaveIdentityExpiration failed: %v", err)
	}

	loadedExp, err := store.LoadIdentityExpiration()
	if err != nil {
		t.Fatalf("LoadIdentityExpiration failed: %v", err)
	}

	if loadedExp != exp {
		t.Errorf("Expected loaded expiration %d, got %d", exp, loadedExp)
	}
}

func TestStore_RefreshToken(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set should fail
	_, err = store.LoadRefreshToken()
	if err == nil {
		t.Error("Expected error loading refresh token when none is saved, got nil")
	}

	token := "refresh-token-xyz"
	if err := store.SaveRefreshToken(token); err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	loaded, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("LoadRefreshToken failed: %v", err)
	}

	if loaded != token {
		t.Errorf("Expected loaded refresh token %q, got %q", token, loaded)
	}
}

func TestStore_OIDCConfig(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set returns empty strings
	iss, cid, aud, err := store.LoadOIDCConfig()
	if err != nil {
		t.Fatalf("LoadOIDCConfig failed: %v", err)
	}
	if iss != "" || cid != "" || aud != "" {
		t.Errorf("Expected empty OIDC config, got issuer=%q, clientID=%q, audience=%q", iss, cid, aud)
	}

	issuer := "https://auth.example.com"
	clientID := "client-123"
	audience := "sam-mesh"

	if err := store.SaveOIDCConfig(issuer, clientID, audience); err != nil {
		t.Fatalf("SaveOIDCConfig failed: %v", err)
	}

	loadedIss, loadedCID, loadedAud, err := store.LoadOIDCConfig()
	if err != nil {
		t.Fatalf("LoadOIDCConfig failed: %v", err)
	}

	if loadedIss != issuer || loadedCID != clientID || loadedAud != audience {
		t.Errorf("Expected OIDC config (%q, %q, %q), got (%q, %q, %q)", issuer, clientID, audience, loadedIss, loadedCID, loadedAud)
	}
}

func TestStore_Key(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set should return nil or empty
	loaded, err := store.LoadKey()
	if err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}
	if len(loaded) > 0 {
		t.Errorf("Expected empty key, got len %d", len(loaded))
	}

	key := []byte("private-key-bytes")
	if err := store.SaveKey(key); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	loaded, err = store.LoadKey()
	if err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}

	if !bytes.Equal(loaded, key) {
		t.Errorf("Expected loaded key %v, got %v", key, loaded)
	}
}

func TestStore_HubConfig(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set
	pubKey, addrs, err := store.LoadHubConfig()
	if err != nil {
		t.Fatalf("LoadHubConfig failed: %v", err)
	}
	if len(pubKey) > 0 || len(addrs) > 0 {
		t.Errorf("Expected empty hub config, got pubKey=%v, addrs=%v", pubKey, addrs)
	}

	hubPubKey := []byte("hub-public-key-bytes")
	hubAddrs := []string{"/ip4/127.0.0.1/tcp/5001", "/dns4/hub.example.com/tcp/5001"}

	if err := store.SaveHubConfig(hubPubKey, hubAddrs); err != nil {
		t.Fatalf("SaveHubConfig failed: %v", err)
	}

	loadedPubKey, loadedAddrs, err := store.LoadHubConfig()
	if err != nil {
		t.Fatalf("LoadHubConfig failed: %v", err)
	}

	if !bytes.Equal(loadedPubKey, hubPubKey) {
		t.Errorf("Expected loaded hub pubkey %v, got %v", hubPubKey, loadedPubKey)
	}
	if !reflect.DeepEqual(loadedAddrs, hubAddrs) {
		t.Errorf("Expected loaded hub addrs %v, got %v", hubAddrs, loadedAddrs)
	}
}

func TestStore_HubURL(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set
	url, err := store.LoadHubURL()
	if err != nil {
		t.Fatalf("LoadHubURL failed: %v", err)
	}
	if url != "" {
		t.Errorf("Expected empty Hub URL, got %q", url)
	}

	hubURL := "https://hub.example.com"
	if err := store.SaveHubURL(hubURL); err != nil {
		t.Fatalf("SaveHubURL failed: %v", err)
	}

	loaded, err := store.LoadHubURL()
	if err != nil {
		t.Fatalf("LoadHubURL failed: %v", err)
	}

	if loaded != hubURL {
		t.Errorf("Expected loaded hub URL %q, got %q", hubURL, loaded)
	}
}

func TestStore_IsBanned(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	pID, err := peer.Decode("12D3KooWBysiyDVxxj7Lq8KvhFnZVhqKdZHtwRaJu7hvGwSZFMNg")
	if err != nil {
		t.Fatalf("Failed to decode peer ID: %v", err)
	}

	// Verify not banned initially
	if store.IsBanned(pID) {
		t.Errorf("Expected peer %s to not be banned", pID)
	}

	// Manually add peer to banned bucket to test IsBanned
	err = store.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("banned_peers"))
		if b == nil {
			return fmt.Errorf("banned_peers bucket not found")
		}
		return b.Put([]byte(pID.String()), []byte("banned"))
	})
	if err != nil {
		t.Fatalf("Failed to manually ban peer: %v", err)
	}

	// Verify banned now
	if !store.IsBanned(pID) {
		t.Errorf("Expected peer %s to be banned", pID)
	}
}

func TestGetDefaultDataDir(t *testing.T) {
	dir, err := GetDefaultDataDir()
	if err != nil {
		t.Fatalf("GetDefaultDataDir failed: %v", err)
	}
	if dir == "" {
		t.Error("Expected non-empty directory path")
	}
}
