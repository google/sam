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
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

func TestTunHint(t *testing.T) {
	notExist := &fs.PathError{Op: "stat", Path: tunDevice, Err: syscall.ENOENT}
	denied := &fs.PathError{Op: "stat", Path: tunDevice, Err: syscall.EACCES}

	for _, tc := range []struct {
		name    string
		err     error
		statErr error
		// want is a phrase naming the fix, so the test fails when the advice
		// stops matching the cause rather than only when the wording changes.
		want string
	}{
		{
			name:    "a guest kernel with no tun driver names CONFIG_TUN",
			err:     syscall.ENODEV,
			statErr: notExist,
			want:    "CONFIG_TUN",
		},
		{
			name:    "a container missing the device is told to pass it in",
			err:     syscall.ENOENT,
			statErr: notExist,
			want:    "--device /dev/net/tun",
		},
		{
			name:    "a pod missing the device is pointed at a hostPath",
			err:     syscall.ENOENT,
			statErr: notExist,
			want:    "hostPath",
		},
		{
			name:    "a device that cannot be opened is not blamed on capabilities",
			statErr: denied,
			err:     syscall.EPERM,
			want:    "cannot be opened",
		},
		{
			name: "a refused create names the capability",
			err:  syscall.EPERM,
			want: "CAP_NET_ADMIN",
		},
		{
			name: "EACCES is treated as EPERM is",
			err:  syscall.EACCES,
			want: "CAP_NET_ADMIN",
		},
		{
			name: "the kernel driver case is named even when the device exists",
			err:  syscall.ENODEV,
			want: "CONFIG_TUN=y",
		},
		{
			name: "an unrecognised cause says so rather than guessing",
			err:  errors.New("something else entirely"),
			want: "not one this knows how to explain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tunHint(tc.err, tc.statErr)
			if !strings.Contains(got, tc.want) {
				t.Errorf("tunHint(%v, %v) = %q, want it to mention %q", tc.err, tc.statErr, got, tc.want)
			}
		})
	}
}

func TestIsolationError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		links   []string
		wantErr bool
		// names is what the message must mention, so an operator is told which
		// interface is the problem rather than only that there is one.
		names []string
	}{
		{
			name:  "a microVM with no network device",
			links: []string{"lo"},
		},
		{
			name:  "a container run with --network none",
			links: []string{"lo"},
		},
		{
			name:  "our own tun, from an earlier run in this namespace",
			links: []string{"lo", tunName},
		},
		{
			name:    "a Kubernetes pod, where the namespace is shared",
			links:   []string{"lo", "eth0"},
			wantErr: true,
			names:   []string{"eth0"},
		},
		{
			name:    "a docker run that forgot --network none",
			links:   []string{"lo", "eth0", tunName},
			wantErr: true,
			names:   []string{"eth0"},
		},
		{
			name:    "several ways out are all reported",
			links:   []string{"lo", "eth0", "vlan7"},
			wantErr: true,
			names:   []string{"eth0", "vlan7"},
		},
		{
			// A namespace with nothing at all is not one we built, but it has
			// no way out either, which is the only property being asserted.
			name:  "an empty namespace",
			links: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := isolationError(tc.links)
			if tc.wantErr && err == nil {
				t.Fatalf("isolationError(%q) = nil, want an error: an agent here is not confined", tc.links)
			}
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("isolationError(%q) = %v, want nil", tc.links, err)
				}
				return
			}
			for _, name := range tc.names {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("error does not name %q, so it does not say what to fix: %v", name, err)
				}
			}
		})
	}
}
