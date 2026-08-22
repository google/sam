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

// Command nano-init is PID 1 in an agent sandbox.
//
// It gives the sandbox one route, which leads to the boundary, and then gets
// out of the agent's way.
//
// It used to do the opposite. It rewrote /etc/resolv.conf to point at a DNS
// server it ran itself, answered lookups with addresses it invented, injected
// HTTP_PROXY and friends into the agent's environment, and preloaded a shared
// object into the agent's address space to catch the connections that got past
// all that. Every one of those asks the agent to cooperate, and an agent that
// has to cooperate with its own confinement is not confined: the next library
// that ignores the proxy variables, the next subprocess that clears its
// environment, the next static binary with no loader to preload into, each one
// was outside the boundary.
//
// Routing does not ask. There is no interface in this sandbox except the tun,
// and the tun goes to the boundary, so an agent that ignores every convention
// here still reaches only what policy allowed. The resolver that remains is a
// convenience for clients that look a name up before connecting, not a control:
// an agent that resolves some other way is routed through the tun regardless.
//
// The TCP stack is gVisor's, via tun2socks. Writing one would mean writing
// retransmission, windowing and teardown, and getting those subtly wrong shows
// up as tail latency under load, which is exactly where this has to be
// trusted.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
)

const (
	tunName = "tun0"

	// Addresses inside the sandbox are link-local because that is what these
	// addresses are for: RFC 3927 describes a single link with no router, and
	// a tun to the boundary is exactly that. A sandbox numbered out of
	// 10.0.0.0/8 will eventually be deployed somewhere that already uses it.
	tunIP   = "169.254.1.1"
	tunAddr = tunIP + "/30"

	// The resolver answers on the tun's own address, which is the one address
	// this sandbox is certain to have. Nothing outside can reach it: a
	// link-local address is not routed anywhere.
	dnsAddr = tunIP + ":53"

	// Disjoint from tunAddr: an overlap would hand out the interface's own
	// address as a name's answer, which fails in a way nobody enjoys reading.
	virtualPool = "169.254.64.0/18"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "copy":
		if len(os.Args) != 3 {
			log.Fatalf("usage: %s copy <dest>", os.Args[0])
		}
		src, err := os.Executable()
		if err != nil {
			src = "/nano-init"
		}
		if err := copyFile(src, os.Args[2]); err != nil {
			log.Fatalf("copy binary: %v", err)
		}

	case "run":
		createNS, ingressSocket, args := parseRunFlags(os.Args[2:])
		if len(args) < 2 {
			usage()
		}
		run(createNS, ingressSocket, args[0], args[1], args[2:])

	default:
		usage()
	}
}

// parseRunFlags reads our own flags and stops at the first argument that is not
// one, because everything after that belongs to the agent and must reach it
// untouched.
func parseRunFlags(args []string) (createNS bool, ingressSocket string, rest []string) {
	for len(args) > 0 {
		switch {
		case args[0] == "--create-namespaces":
			createNS, args = true, args[1:]
		case args[0] == "--ingress-socket":
			if len(args) < 2 {
				log.Fatalf("--ingress-socket needs a path")
			}
			ingressSocket, args = args[1], args[2:]
		case strings.HasPrefix(args[0], "--ingress-socket="):
			ingressSocket, args = strings.TrimPrefix(args[0], "--ingress-socket="), args[1:]
		default:
			return createNS, ingressSocket, args
		}
	}
	return createNS, ingressSocket, nil
}

// runFlags rebuilds the arguments for the re-executed half, so it is given
// what this one was given.
func runFlags(ingressSocket, boundarySocket, cmdName string, cmdArgs []string) []string {
	args := []string{"run", "--create-namespaces"}
	if ingressSocket != "" {
		args = append(args, "--ingress-socket", ingressSocket)
	}
	args = append(args, boundarySocket, cmdName)
	return append(args, cmdArgs...)
}

func usage() {
	log.Fatalf("usage:\n  %s copy <dest>\n  %s run [--create-namespaces] [--ingress-socket <path>] <boundary-socket> <cmd> [args...]",
		os.Args[0], os.Args[0])
}

// run wires the sandbox up and hands it to the agent.
func run(createNS bool, ingressSocket, boundarySocket, cmdName string, cmdArgs []string) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	// The namespaces have to exist before anything is checked in them, and a
	// whole Go program can only enter a new network namespace by being started
	// in one. So this half makes them and becomes a supervisor; the half that
	// comes back through here does the work.
	if createNS && !insideCreatedNamespaces() {
		userNS, err := needUserNamespace()
		if err != nil {
			log.Fatalf("refusing to start: %v", err)
		}
		self, err := os.Executable()
		if err != nil {
			log.Fatalf("locate this binary to re-execute it: %v", err)
		}
		args := runFlags(ingressSocket, boundarySocket, cmdName, cmdArgs)
		code, err := runAgent(ctx, cancel, self, args, withNamespaces(userNS))
		if err != nil {
			log.Fatalf("create the sandbox namespaces: %v\n%s", err, namespaceHint(err))
		}
		os.Exit(code)
	}

	if createNS {
		if err := privateResolvConf(); err != nil {
			log.Fatalf("refusing to start: %v", err)
		}
	}

	// First, and before anything is built: if this namespace is not a sandbox
	// then the boundary is beside the point, and saying so in that order is
	// the difference between "you forgot --network none" and a puzzling
	// complaint about a socket.
	if err := assertIsolated(); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	if err := checkBoundary(boundarySocket); err != nil {
		log.Fatalf("this sandbox has no way out: %v", err)
	}

	names, err := newResolver(virtualPool)
	if err != nil {
		log.Fatalf("resolver: %v", err)
	}
	if err := setupNetwork(ctx, boundarySocket, names); err != nil {
		log.Fatalf("set up sandbox network: %v", err)
	}

	// Started here rather than earlier because it only makes sense once the
	// sandbox exists: this is the one process that can reach the agent at the
	// address the gateway will name.
	if ingressSocket != "" {
		go func() {
			if err := serveIngress(ctx, ingressSocket); err != nil {
				log.Printf("ingress: %v", err)
			}
		}()
	}

	code, err := runAgent(ctx, cancel, cmdName, cmdArgs)
	if err != nil {
		log.Fatalf("start agent: %v", err)
	}
	os.Exit(code)
}

// setupNetwork builds the only route out of the sandbox.
//
// This talks netlink rather than shelling out to `ip`, and carries its own TCP
// stack rather than running a separate binary, so a sandbox image can be the
// agent and nothing else. That is not tidiness: image size is what decides how
// many agents fit on a host.
func setupNetwork(ctx context.Context, boundarySocket string, names *resolver) error {
	// As PID 1 in a microVM nothing else has done this, and a sandbox without
	// loopback breaks things that have no business caring about the network.
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}

	tun := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: tunName},
		Mode:      netlink.TUNTAP_MODE_TUN,
	}
	if err := netlink.LinkAdd(tun); err != nil {
		return fmt.Errorf("create %s: %w\n%s", tunName, err, describeTunFailure(err))
	}
	if err := netlink.LinkSetUp(tun); err != nil {
		return fmt.Errorf("bring up %s: %w", tunName, err)
	}

	addr, err := netlink.ParseAddr(tunAddr)
	if err != nil {
		return fmt.Errorf("parse %s: %w", tunAddr, err)
	}
	if err := netlink.AddrAdd(tun, addr); err != nil {
		return fmt.Errorf("address %s: %w", tunName, err)
	}

	// A device route with no gateway: nothing on the far side of this link has
	// an address worth naming, and everything goes the same way regardless.
	// The destination has to be spelled out rather than left nil, which
	// netlink reads as "no route specified at all".
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: tun.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
	}); err != nil {
		return fmt.Errorf("default route via %s: %w", tunName, err)
	}

	dns, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		return fmt.Errorf("resolver on %s: %w", dnsAddr, err)
	}
	go names.serveDNS(dns)
	go func() {
		<-ctx.Done()
		_ = dns.Close()
	}()

	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver "+tunIP+"\n"), 0o644); err != nil {
		// Not fatal: resolution is a convenience here, not the control.
		log.Printf("could not write /etc/resolv.conf, name resolution may fail: %v", err)
	}

	// direct:// is a placeholder the engine insists on. The real dialer is
	// installed below, before the agent exists to send anything, so nothing
	// can take the placeholder path.
	engine.Insert(&engine.Key{
		Device:   "tun://" + tunName,
		Proxy:    "direct://",
		LogLevel: "warn",
	})
	engine.Start()

	tunnel.T().SetProxy(&boundaryProxy{socket: boundarySocket, resolver: names})
	return nil
}

// runAgent starts the agent and reports the exit status it should be judged by.
//
// The same supervision serves the namespace trampoline, whose child is this
// binary again: orphans still reparent here and still have to be reaped, and
// the exit code still has to be the one the caller sees.
func runAgent(ctx context.Context, cancel context.CancelFunc, cmdName string, cmdArgs []string, opts ...func(*exec.Cmd)) (int, error) {
	cmd := exec.CommandContext(ctx, cmdName, cmdArgs...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	cmd.Env = os.Environ() // Nothing injected: the agent is not configured, it is routed.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	for _, opt := range opts {
		opt(cmd)
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		// Returned rather than fatal: the namespace trampoline starts this same
		// binary, and a refusal there means something quite different.
		return 0, err
	}

	// As PID 1 this process inherits every orphan in the sandbox, so it has to
	// reap them or the guest fills with zombies. Reaping also means Wait can
	// lose the race for the agent's own status, hence the channel.
	agentExit := make(chan syscall.WaitStatus, 1)
	reapChildren(cmd.Process.Pid, agentExit)

	waitErr := cmd.Wait()
	cancel()

	if waitErr != nil && errors.Is(waitErr, syscall.ECHILD) {
		status := <-agentExit
		if status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return status.ExitStatus(), nil
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, nil
	}
	return 0, nil
}

// reapChildren collects orphans and remembers the agent's own status.
func reapChildren(agentPid int, exitChan chan<- syscall.WaitStatus) {
	sigCh := make(chan os.Signal, 10)
	signal.Notify(sigCh, syscall.SIGCHLD)

	go func() {
		reap := func() {
			for {
				var status syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					return
				}
				if pid == agentPid {
					select {
					case exitChan <- status:
					default:
					}
				}
			}
		}
		// Once before waiting on signals, to catch anything that exited
		// between Start and Notify.
		reap()
		for range sigCh {
			reap()
		}
	}()
}
