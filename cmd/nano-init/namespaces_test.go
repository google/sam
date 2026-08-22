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
	"os/exec"
	"syscall"
	"testing"
)

func TestCapSysAdminFromStatus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  string
		want    bool
		wantErr bool
	}{
		{
			name:   "a full capability set has it",
			status: "Name:\tnano-init\nCapEff:\t000001ffffffffff\n",
			want:   true,
		},
		{
			name: "a pod's default set does not",
			// What a container gets without securityContext: no CAP_SYS_ADMIN,
			// which is the case that has to fall back to a user namespace.
			status: "Name:\tnano-init\nCapEff:\t00000000a80425fb\n",
			want:   false,
		},
		{
			name:   "an empty set does not",
			status: "CapEff:\t0000000000000000\n",
			want:   false,
		},
		{
			name:   "exactly CAP_SYS_ADMIN and nothing else",
			status: "CapEff:\t0000000000200000\n",
			want:   true,
		},
		{
			name:    "a status with no CapEff line is an error, not a false",
			status:  "Name:\tnano-init\nPid:\t1\n",
			wantErr: true,
		},
		{
			name:    "an unparseable set is an error, not a false",
			status:  "CapEff:\tnonsense\n",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := capSysAdminFromStatus(tc.status)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("capSysAdminFromStatus(%q) = %v, want an error: guessing here decides whether a sandbox is isolated", tc.status, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("capSysAdminFromStatus(%q): %v", tc.status, err)
			}
			if got != tc.want {
				t.Errorf("capSysAdminFromStatus(%q) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestWithNamespaces(t *testing.T) {
	t.Run("always makes a network and a mount namespace", func(t *testing.T) {
		cmd := exec.Command("/bin/true")
		withNamespaces(false)(cmd)

		if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET == 0 {
			t.Error("no CLONE_NEWNET: the sandbox would share the pod's network")
		}
		// Unshareflags rather than Cloneflags, because that is what makes the
		// runtime mark / private; without it the bind mount over resolv.conf
		// could propagate back to the pod.
		if cmd.SysProcAttr.Unshareflags&syscall.CLONE_NEWNS == 0 {
			t.Error("no CLONE_NEWNS in Unshareflags: mounts could escape the sandbox")
		}
	})

	t.Run("adds a user namespace only when asked", func(t *testing.T) {
		cmd := exec.Command("/bin/true")
		withNamespaces(false)(cmd)

		if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWUSER != 0 {
			t.Error("CLONE_NEWUSER without being asked: it is a fallback, not the default")
		}
		if len(cmd.SysProcAttr.UidMappings) != 0 {
			t.Error("uid mappings without a user namespace to map into")
		}
	})

	t.Run("a user namespace comes with the mapping that makes it usable", func(t *testing.T) {
		cmd := exec.Command("/bin/true")
		withNamespaces(true)(cmd)

		if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWUSER == 0 {
			t.Fatal("no CLONE_NEWUSER: without CAP_SYS_ADMIN there is no other way to make a netns")
		}
		if len(cmd.SysProcAttr.UidMappings) != 1 || cmd.SysProcAttr.UidMappings[0].ContainerID != 0 {
			t.Errorf("uid mappings = %v, want this process mapped to root inside", cmd.SysProcAttr.UidMappings)
		}
		// An unprivileged user namespace may not call setgroups, so asking for
		// it fails the whole clone.
		if cmd.SysProcAttr.GidMappingsEnableSetgroups {
			t.Error("setgroups enabled: an unprivileged user namespace cannot have it")
		}
	})

	t.Run("marks the child so it does not do this again", func(t *testing.T) {
		cmd := exec.Command("/bin/true")
		withNamespaces(false)(cmd)

		var found bool
		for _, kv := range cmd.Env {
			if kv == nsCreatedEnv+"=1" {
				found = true
			}
		}
		if !found {
			t.Errorf("env = %v, want %s: without it the child re-executes forever", cmd.Env, nsCreatedEnv)
		}
	})
}
