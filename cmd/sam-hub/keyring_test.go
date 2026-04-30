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
	"path/filepath"
	"testing"
	"time"
)

func TestNewKeyRing(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	if len(kr.Current.Private) == 0 {
		t.Error("Expected current private key to be initialized")
	}
	if len(kr.Current.Public) == 0 {
		t.Error("Expected current public key to be initialized")
	}
}

func TestKeyRingRotate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	oldPub := kr.Current.Public

	newPub, err := kr.Rotate(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(oldPub, newPub) {
		t.Error("Expected new public key to be different from old public key")
	}

	if len(kr.Previous) != 1 {
		t.Errorf("Expected 1 previous key, got %d", len(kr.Previous))
	}
	if !bytes.Equal(kr.Previous[0].Public, oldPub) {
		t.Error("Expected previous key to match old public key")
	}
}

func TestKeyRingPersistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	currentPub := kr.Current.Public
	_ = kr.Close()

	// Reopen
	kr2, err := NewKeyRing(dbPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr2.Close() }()

	if !bytes.Equal(kr2.Current.Public, currentPub) {
		t.Error("Expected persisted public key to match original")
	}
}

func TestKeyRingCleanup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 1*time.Millisecond) // Short grace period
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	oldPub := kr.Current.Public

	_, err = kr.Rotate(1 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	if len(kr.Previous) != 1 {
		t.Errorf("Expected 1 previous key before expiration, got %d", len(kr.Previous))
	}

	time.Sleep(5 * time.Millisecond) // Wait for expiration

	// Rotate again to trigger cleanup
	_, err = kr.Rotate(1 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// The first previous key should be cleaned up!
	// So we should still have 1 previous key (the one from the second rotation),
	// but its public key should NOT be oldPub!
	if len(kr.Previous) != 1 {
		t.Errorf("Expected 1 previous key after cleanup, got %d", len(kr.Previous))
	}
	if bytes.Equal(kr.Previous[0].Public, oldPub) {
		t.Error("Expected expired key to be pruned")
	}
}
