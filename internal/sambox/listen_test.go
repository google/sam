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

package sambox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sambox")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func TestListenSandboxSocketIsPrivate(t *testing.T) {
	path := tempSocketPath(t, "agent.sock")

	l, err := ListenSandboxSocket(path)
	if err != nil {
		t.Fatalf("ListenSandboxSocket: %v", err)
	}
	defer func() { _ = l.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("socket mode = %o, want 600", perm)
	}
}

// TestListenSandboxSocketReplacesAStaleSocket covers the restart case: a
// gateway that crashed leaves the file behind, and refusing to start would turn
// one crash into a permanent outage.
func TestListenSandboxSocketReplacesAStaleSocket(t *testing.T) {
	path := tempSocketPath(t, "agent.sock")

	first, err := ListenSandboxSocket(path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Closing a Unix listener removes the file, so put it back to model the
	// crash that never got to clean up.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("recreate socket: %v", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale: %v", err)
	}

	second, err := ListenSandboxSocket(path)
	if err != nil {
		t.Fatalf("ListenSandboxSocket over a stale socket: %v", err)
	}
	_ = second.Close()
}

// TestListenSandboxSocketRefusesALiveGateway is the other half: replacing a
// socket somebody is still answering on would silently steal their agents.
func TestListenSandboxSocketRefusesALiveGateway(t *testing.T) {
	path := tempSocketPath(t, "agent.sock")

	live, err := ListenSandboxSocket(path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	defer func() { _ = live.Close() }()
	go func() {
		for {
			conn, err := live.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	if _, err := ListenSandboxSocket(path); err == nil {
		t.Fatal("ListenSandboxSocket replaced a live gateway, want an error")
	}
}

func TestListenSandboxSocketRejectsBadPaths(t *testing.T) {
	t.Run("not a socket", func(t *testing.T) {
		path := tempSocketPath(t, "agent.sock")
		if err := os.WriteFile(path, []byte("not a socket"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := ListenSandboxSocket(path); err == nil {
			t.Fatal("ListenSandboxSocket accepted a regular file, want an error")
		}
	})

	t.Run("too long for the kernel", func(t *testing.T) {
		path := tempSocketPath(t, strings.Repeat("a", 120)+".sock")
		if _, err := ListenSandboxSocket(path); err == nil {
			t.Fatal("ListenSandboxSocket accepted an over-long path, want an error")
		}
	})
}
