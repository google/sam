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
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mdlayher/vsock"
)

// A sandbox reaches its boundary one of two ways, and the difference is the
// only thing that distinguishes a container from a microVM here.
//
// A container gets the socket bind-mounted in, so it dials a path. A microVM
// has no shared filesystem and no network device, so it dials vsock, and
// Firecracker delivers that to a Unix socket on the host named
// "<uds_path>_<port>". Both arrive at the same sam-box, which is why one binary
// serves both and nothing else in the sandbox knows which kind it is.
//
// The vsock socket work is a library rather than forty lines of syscalls here.
// It was forty lines of syscalls, and they were wrong: net.FileConn refuses an
// AF_VSOCK descriptor outright, and the replacement leaned on os.File's poller
// registration for deadlines, which degrades silently to no deadlines at all if
// registration fails. Both are the kind of mistake that surfaces as a hung flow
// under load rather than an error at startup. This module already carries a
// TCP stack, so a thousand lines of well-exercised socket handling is not the
// dependency worth economising on.

const vsockScheme = "vsock://"

// dialBoundary opens a connection to the boundary named by spec, which is
// either "vsock://<cid>:<port>" or a Unix socket path.
func dialBoundary(ctx context.Context, spec string) (net.Conn, error) {
	if !strings.HasPrefix(spec, vsockScheme) {
		return (&net.Dialer{Timeout: boundaryDialTimeout}).DialContext(ctx, "unix", spec)
	}

	cid, port, err := parseVsock(strings.TrimPrefix(spec, vsockScheme))
	if err != nil {
		return nil, err
	}
	// There is no context-aware Dial, and none is needed: the peer is the
	// hypervisor on the other side of a virtual bus, so this either succeeds
	// or fails immediately rather than waiting on anything that could hang.
	return vsock.Dial(cid, port, nil)
}

// checkBoundary reports whether the boundary named by spec could plausibly be
// reached, so a sandbox with no way out says so at startup rather than on the
// agent's first request.
func checkBoundary(spec string) error {
	if strings.HasPrefix(spec, vsockScheme) {
		if _, _, err := parseVsock(strings.TrimPrefix(spec, vsockScheme)); err != nil {
			return err
		}
		// Whether the host is listening cannot be known without connecting,
		// and connecting here would consume a flow the agent has not asked for.
		return nil
	}
	if _, err := os.Stat(spec); err != nil {
		return fmt.Errorf("no boundary at %s: %w", spec, err)
	}
	return nil
}

func parseVsock(hostPort string) (cid, port uint32, err error) {
	rawCID, rawPort, found := strings.Cut(hostPort, ":")
	if !found {
		return 0, 0, fmt.Errorf("vsock boundary %q is not <cid>:<port>", hostPort)
	}

	parsedCID, err := strconv.ParseUint(rawCID, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("vsock cid %q: %w", rawCID, err)
	}
	parsedPort, err := strconv.ParseUint(rawPort, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("vsock port %q: %w", rawPort, err)
	}
	return uint32(parsedCID), uint32(parsedPort), nil
}
