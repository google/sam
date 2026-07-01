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

package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestSamNodeRunWithStoredIdentity(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	tmpHome := t.TempDir()

	// Pre-populate store
	configDir := filepath.Join(tmpHome, ".config", "sam-mesh")
	err := os.MkdirAll(configDir, 0700)
	if err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	dbPath := filepath.Join(configDir, "agent.db")
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("identity"))
		if err != nil {
			return err
		}
		// The following constants are mock values used for testing.
		// 'mock-biscuit-token' is a dummy token string.
		// 'mock-hub-pub-key' is a dummy public key string.
		if err := b.Put([]byte("identity_biscuit"), []byte("mock-biscuit-token")); err != nil {
			return err
		}
		if err := b.Put([]byte("hub_public_key"), []byte("mock-hub-pub-key")); err != nil {
			return err
		}
		addrsData, _ := json.Marshal([]string{"/ip4/127.0.0.1/tcp/4002/p2p/Qm..."})
		if err := b.Put([]byte("hub_addresses"), addrsData); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to update db: %v", err)
	}
	_ = db.Close()

	env := append(os.Environ(), "HOME="+tmpHome)

	runOut, runErrOut, err := runCommand(
		t,
		repoRoot(t),
		3*time.Second,
		env,
		"",
		nodeBin,
		"run", "--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", "dummy-token",
		"--data-dir", configDir,
	)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected run command to keep running until timeout, got: %v\nstdout:\n%s\nstderr:\n%s", err, runOut, runErrOut)
	}
	t.Logf("stdout:\n%s\nstderr:\n%s", runOut, runErrOut)

	out := runOut + runErrOut
	if !strings.Contains(out, "Using stored identity.") {
		t.Fatalf("run command did not use stored identity:\n%s", out)
	}
	if !strings.Contains(out, "SAM Node Online") {
		t.Fatalf("node did not reach online state:\n%s", out)
	}
}
