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
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
)

func TestGetOrGenerateKey(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// First call should generate a key
	key1 := getOrGenerateKey(store)
	if key1 == nil {
		t.Fatal("Expected key to be generated")
	}

	// Second call should retrieve the same key
	key2 := getOrGenerateKey(store)
	if key2 == nil {
		t.Fatal("Expected key to be retrieved")
	}

	// Verify they are the same key
	raw1, _ := crypto.MarshalPrivateKey(key1)
	raw2, _ := crypto.MarshalPrivateKey(key2)
	if !bytes.Equal(raw1, raw2) {
		t.Error("Expected retrieved key to match generated key")
	}
}


