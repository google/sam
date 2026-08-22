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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// maxUnixPathLen is the kernel's sun_path budget. Overflowing it only yields
// "invalid argument" from bind(2), which is not a useful thing to hand an
// operator.
const maxUnixPathLen = 104

// ListenSandboxSocket binds the sandbox-facing socket. A socket left behind by
// a crashed gateway is replaced; one a live gateway is still answering on is
// not.
//
// The socket is created 0600. For a microVM that is exactly right, since
// firecracker connects to it as the same user. For a container whose sandbox
// runs as a different uid, the platform has to align ownership when it creates
// the sandbox — which is where per-agent sockets will be created once admission
// exists, and the only place that knows which uid to use.
func ListenSandboxSocket(path string) (net.Listener, error) {
	if len(path) >= maxUnixPathLen {
		return nil, fmt.Errorf("socket path %q is too long (%d bytes, the kernel allows %d)", path, len(path), maxUnixPathLen-1)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating the socket directory: %w", err)
	}

	if info, err := os.Stat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s already exists and is not a socket", path)
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("another gateway is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing the stale socket %s: %w", path, err)
		}
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restricting access to %s: %w", path, err)
	}
	return listener, nil
}
