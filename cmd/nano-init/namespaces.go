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
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Creating the sandbox is normally somebody else's job: `docker run
// --network none` and a microVM's own kernel both hand this process a
// namespace with nowhere to go. A Kubernetes pod does not, and cannot -- every
// container in a pod shares one network namespace, and the resolv.conf the
// kubelet writes is shared with them too -- so for that profile the namespaces
// have to be made here, from inside the container.
//
// This is opt-in rather than automatic. A sandbox that quietly creates its own
// isolation when it cannot find any is a sandbox that never reports a
// misconfigured runtime, and the two profiles that do get isolation from their
// runtime should keep failing loudly when it is missing.

// nsCreatedEnv marks the re-executed child, so it sets the namespaces up once
// rather than forever.
const nsCreatedEnv = "NANO_INIT_NAMESPACES_CREATED"

// capSysAdmin is the capability that creating a network namespace requires.
const capSysAdmin = 21

// insideCreatedNamespaces reports whether this process is the re-executed half.
func insideCreatedNamespaces() bool {
	return os.Getenv(nsCreatedEnv) == "1"
}

// withNamespaces makes the child the first process in a new network and mount
// namespace, adding a user namespace when that is the only way to be allowed.
//
// The work happens in a child because unshare(CLONE_NEWNET) moves one thread,
// and the Go runtime has several that goroutines migrate between: the only way
// to get a whole program into a new network namespace is to start one there.
func withNamespaces(userNS bool) func(*exec.Cmd) {
	return func(c *exec.Cmd) {
		if c.SysProcAttr == nil {
			c.SysProcAttr = &syscall.SysProcAttr{}
		}
		c.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
		// Unshareflags rather than Cloneflags: the runtime also makes / private
		// that way, so a bind mount below cannot propagate back to the pod.
		c.SysProcAttr.Unshareflags |= syscall.CLONE_NEWNS

		if userNS {
			c.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
			c.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: os.Getuid(), Size: 1},
			}
			c.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: os.Getgid(), Size: 1},
			}
			// Denied because an unprivileged user namespace may not call it,
			// and nothing in a sandbox needs supplementary groups.
			c.SysProcAttr.GidMappingsEnableSetgroups = false
		}

		c.Env = append(c.Env, nsCreatedEnv+"=1")
	}
}

// needUserNamespace decides how to get permission to create a network
// namespace, or explains why neither way is open.
//
// A user namespace is preferred rather than merely tolerated. Inside one this
// process is root over the namespaces it then creates, which supplies
// CAP_NET_ADMIN for building the tun as well as CAP_SYS_ADMIN for making the
// namespace at all. Taking the capability route instead needs both to have been
// granted: a container given CAP_SYS_ADMIN but not CAP_NET_ADMIN creates the
// namespace and then cannot build the route out of it, which is a worse failure
// than not starting.
//
// So the capability route is the fallback, for hosts where user namespaces are
// turned off.
func needUserNamespace() (bool, error) {
	userNSErr := userNamespacesAvailable()
	if userNSErr == nil {
		return true, nil
	}
	has, err := hasCapSysAdmin()
	if err != nil {
		return false, err
	}
	if has {
		return false, nil
	}
	return false, fmt.Errorf(
		"cannot create a network namespace: %w, and this process has no CAP_SYS_ADMIN. "+
			"Allow unprivileged user namespaces, or grant CAP_SYS_ADMIN and CAP_NET_ADMIN", userNSErr)
}

// namespaceHint explains a refusal to create the namespaces.
//
// The kernel says EPERM and stops there, but in a container the cause is
// usually a sandboxing policy rather than a missing capability, and those are
// not visible from in here.
func namespaceHint(err error) string {
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		return ""
	}
	return "This is usually the runtime's own sandboxing rather than a missing capability. " +
		"Docker's default seccomp profile blocks creating a user namespace, and its default " +
		"AppArmor profile blocks the mount that follows; Kubernetes applies neither unless asked, " +
		"so a pod normally needs no securityContext for this at all. Where a profile is enforced, " +
		"it has to permit unshare(CLONE_NEWUSER|CLONE_NEWNS) and mount."
}

// hasCapSysAdmin reads the effective capability set of this process.
func hasCapSysAdmin() (bool, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, fmt.Errorf("read capabilities: %w", err)
	}
	return capSysAdminFromStatus(string(status))
}

// capSysAdminFromStatus finds CAP_SYS_ADMIN in the CapEff line of a
// /proc/<pid>/status.
func capSysAdminFromStatus(status string) (bool, error) {
	for _, line := range strings.Split(status, "\n") {
		hex, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		caps, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
		if err != nil {
			return false, fmt.Errorf("parse CapEff %q: %w", strings.TrimSpace(hex), err)
		}
		return caps&(1<<capSysAdmin) != 0, nil
	}
	return false, fmt.Errorf("no CapEff line in /proc/self/status")
}

// userNamespacesAvailable reports why an unprivileged user namespace would be
// refused, so the failure names a sysctl rather than an errno.
func userNamespacesAvailable() error {
	if max, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(max))); err == nil && n == 0 {
			return fmt.Errorf("user namespaces are disabled (user.max_user_namespaces is 0)")
		}
	}
	// Debian and derivatives carry this one separately.
	if allowed, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(allowed)) == "0" {
			return fmt.Errorf("unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone is 0)")
		}
	}
	return nil
}

// mountHint explains a refused mount, which in a container is usually a
// sandboxing profile rather than a missing capability.
//
// Kubernetes is the case worth naming. containerd applies an AppArmor profile
// by default -- cri-containerd.apparmor.d on GKE -- and it denies bind mounts
// while allowing the namespace itself, so the sandbox gets as far as having a
// mount namespace and then cannot put anything in it.
func mountHint(err error) string {
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		return ""
	}
	return " This is usually AppArmor rather than a missing capability: containerd applies a" +
		" profile that denies bind mounts. In a pod, set the agent container's" +
		" securityContext.appArmorProfile.type to Unconfined, or load a profile that permits" +
		" mount. Docker's equivalent is --security-opt apparmor=unconfined."
}

// A new mount namespace copies the mount table; it does not copy files. The
// resolv.conf a pod hands each container is one file shared by all of them, so
// without this, pointing DNS at the sandbox's own resolver would point every
// container in the pod at it.
//
// Only the privacy is arranged here. What goes in the file is setupNetwork's
// business, and it writes through this mount.
func privateResolvConf() error {
	f, err := os.CreateTemp("", "resolv.conf")
	if err != nil {
		return fmt.Errorf(
			"a private resolv.conf needs somewhere writable to live, and this sandbox has nowhere: %w. "+
				"Give the container a writable /tmp, or an emptyDir mounted there", err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		return fmt.Errorf("close the private resolv.conf: %w", err)
	}
	if err := unix.Mount(name, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("bind a private resolv.conf over /etc/resolv.conf: %w.%s", err, mountHint(err))
	}
	// The mount holds the inode, so the path it was reached by is litter.
	_ = os.Remove(name)
	return nil
}
