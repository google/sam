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

// TestMeshDiscovery is an end-to-end integration test for the SAM mesh:
//
//  Agent 1 ("publisher") starts a DHT server node, signs an AgentCard with
//  the "agent.summarize" capability, publishes it to the DHT, and registers
//  an MCP bridge backed by a loopback echo connector.
//
//  Agent 2 ("subscriber") starts an independent DHT server node, connects to
//  Agent 1 as its bootstrap peer, discovers the published card via DHT, opens
//  a QUIC stream through the MCP bridge, and verifies the echo round-trip.
//
// Each agent runs in its own isolated network namespace (CLONE_NEWNET +
// CLONE_NEWUSER). The test parent creates a veth pair and configures it using
// the vishvananda/netlink library — no external tools required.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"sam/internal/testutils"
	"sam/pkg/economy"
	"sam/pkg/identity"
	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	meshHelperEnv      = "SAM_MESH_HELPER"
	meshRoleEnv        = "SAM_MESH_ROLE"
	meshInfoEnv        = "SAM_MESH_INFO_FILE"
	meshIPEnv          = "SAM_MESH_IP"
	meshPortEnv        = "SAM_MESH_PORT"
	meshPublisherRole  = "publisher"
	meshSubscriberRole = "subscriber"
	meshPublisherIP    = "10.200.0.1"
	meshSubscriberIP   = "10.200.0.2"
	meshPublisherPort  = 4201
	meshSubscriberPort = 4202
	meshCapability     = "weather-bot"
)

type meshPeerInfo struct {
	PeerID    string `json:"peer_id"`
	Bootstrap string `json:"bootstrap"`
}

// ---------------------------------------------------------------------------
// Top-level test entry point
// ---------------------------------------------------------------------------

// TestMeshDiscovery is the public test function.  When re-invoked as a helper
// subprocess it dispatches to the appropriate agent role.
func TestMeshDiscovery(t *testing.T) {
	if os.Getenv(meshHelperEnv) == "1" {
		if err := runMeshHelperRole(); err != nil {
			t.Fatalf("mesh helper failed: %v", err)
		}
		return
	}

	testutils.Run(t, func(t *testing.T) {
		runMeshDiscovery(t)
	}, syscall.CLONE_NEWNET)
}

// ---------------------------------------------------------------------------
// Orchestrator (runs in the outer user+net namespace)
// ---------------------------------------------------------------------------

func runMeshDiscovery(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()
	infoFile := filepath.Join(tmpDir, "publisher.json")

	publisher := startMeshRoleProcess(t, meshPublisherRole, infoFile, meshPublisherIP, meshPublisherPort)
	defer stopMeshRoleProcess(publisher)

	subscriber := startMeshRoleProcess(t, meshSubscriberRole, infoFile, meshSubscriberIP, meshSubscriberPort)
	defer stopMeshRoleProcess(subscriber)

	// Assign veth interfaces before unblocking either agent so that both have
	// network connectivity from the moment they start QUIC listeners.
	configureMeshVethPair(t, publisher.cmd.Process.Pid, subscriber.cmd.Process.Pid)

	if _, err := io.WriteString(publisher.stdin, "start\n"); err != nil {
		t.Fatalf("unblocking publisher: %v", err)
	}
	if _, err := io.WriteString(subscriber.stdin, "start\n"); err != nil {
		t.Fatalf("unblocking subscriber: %v", err)
	}

	// Wait for publisher to be ready before checking subscriber exit.
	if err := waitForMeshInfoFile(infoFile, 15*time.Second); err != nil {
		t.Fatalf("publisher did not write info file in time: %v\npublisher stdout:\n%s\npublisher stderr:\n%s",
			err, publisher.stdout.String(), publisher.stderr.String())
	}

	waitMeshRoleExit(t, subscriber, 35*time.Second)
	if subscriber.cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("subscriber process failed\nstdout:\n%s\nstderr:\n%s",
			subscriber.stdout.String(), subscriber.stderr.String())
	}
}

// ---------------------------------------------------------------------------
// Subprocess helper dispatcher
// ---------------------------------------------------------------------------

func runMeshHelperRole() error {
	// The orchestrator sends a single "start\n" line after configuring the
	// network so that both agents have IP connectivity before they open ports.
	reader := bufio.NewReader(os.Stdin)
	if _, err := reader.ReadString('\n'); err != nil {
		return fmt.Errorf("waiting for mesh start signal: %w", err)
	}

	switch os.Getenv(meshRoleEnv) {
	case meshPublisherRole:
		return runMeshPublisher()
	case meshSubscriberRole:
		return runMeshSubscriber()
	default:
		return fmt.Errorf("unknown mesh role %q", os.Getenv(meshRoleEnv))
	}
}

// ---------------------------------------------------------------------------
// Agent 1 — Publisher
// ---------------------------------------------------------------------------

func runMeshPublisher() error {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	port, err := parseMeshPort()
	if err != nil {
		return err
	}

	node, err := newMeshNode(port, samnet.DHTModeServer, nil)
	if err != nil {
		return err
	}
	if err := node.Start(ctx); err != nil {
		return fmt.Errorf("publisher node start: %w", err)
	}
	if err := meshConfigureNodePassport(ctx, node, "publisher"); err != nil {
		return fmt.Errorf("publisher passport setup: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	// Write the peer info before publishing so the subscriber can start
	// connecting as soon as the DHT bootstrap is ready.
	bootstrapAddr := fmt.Sprintf("/ip4/%s/udp/%d/quic-v1/p2p/%s",
		os.Getenv(meshIPEnv), port, node.PeerID())
	info := meshPeerInfo{PeerID: node.PeerID().String(), Bootstrap: bootstrapAddr}
	if err := writeMeshPeerInfo(os.Getenv(meshInfoEnv), info); err != nil {
		return err
	}

	priv := node.Host().Peerstore().PrivKey(node.PeerID())
	card, err := protocol.NewAgentCard(
		node.PeerID(),
		[]string{meshCapability},
		[]protocol.MCPResource{{Name: "summarizer", Kind: "tool", Endpoint: "mcp://summarizer"}},
		priv,
	)
	if err != nil {
		return fmt.Errorf("publisher card creation: %w", err)
	}

	pub, err := protocol.NewPublisher(node)
	if err != nil {
		return fmt.Errorf("publisher: %w", err)
	}
	if err := meshPublishWithRetry(ctx, pub, card); err != nil {
		return fmt.Errorf("publisher publish: %w", err)
	}

	discovery, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return fmt.Errorf("publisher discovery service: %w", err)
	}
	if err := discovery.RegisterLocalCard(card); err != nil {
		return fmt.Errorf("publisher register card: %w", err)
	}

	// meshAllowVerifier accepts any token so the subscriber test needs no real Biscuit token.
	if _, err := protocol.NewMCPBridge(node.Host(), meshAllowVerifier{}, meshEchoConnector{}); err != nil {
		return fmt.Errorf("publisher bridge setup: %w", err)
	}

	// Stay online until the context is cancelled (subscriber completed or timeout).
	<-ctx.Done()
	return nil
}

// ---------------------------------------------------------------------------
// Agent 2 — Subscriber
// ---------------------------------------------------------------------------

func runMeshSubscriber() error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	port, err := parseMeshPort()
	if err != nil {
		return err
	}

	info, err := waitMeshPeerInfo(ctx, os.Getenv(meshInfoEnv))
	if err != nil {
		return err
	}

	bootstrap, err := multiaddr.NewMultiaddr(info.Bootstrap)
	if err != nil {
		return fmt.Errorf("parsing bootstrap addr: %w", err)
	}
	publisherID, err := peer.Decode(info.PeerID)
	if err != nil {
		return fmt.Errorf("decoding publisher peer ID: %w", err)
	}
	publisherAddrInfo, err := peer.AddrInfoFromP2pAddr(bootstrap)
	if err != nil {
		return fmt.Errorf("building publisher addr info: %w", err)
	}

	// Both peers must run as DHT servers in an isolated two-node mesh so that
	// DHT records are visible to each other without external routing tables.
	node, err := newMeshNode(port, samnet.DHTModeServer, []multiaddr.Multiaddr{bootstrap})
	if err != nil {
		return err
	}
	if err := node.Start(ctx); err != nil {
		return fmt.Errorf("subscriber node start: %w", err)
	}
	if err := meshConfigureNodePassport(ctx, node, "subscriber"); err != nil {
		return fmt.Errorf("subscriber passport setup: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	if err := meshConnectWithRetry(ctx, node, *publisherAddrInfo); err != nil {
		return fmt.Errorf("connecting to publisher bootstrap: %w", err)
	}

	discovery, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return fmt.Errorf("subscriber discovery service: %w", err)
	}

	// 1. Discover the published capability via DHT and connect.
	peerIDs, err := meshDiscoverAndConnectWithRetry(ctx, discovery, meshCapability)
	if err != nil {
		return fmt.Errorf("subscriber DHT discovery failed: %w", err)
	}
	if len(peerIDs) == 0 {
		return fmt.Errorf("expected at least one peer for capability %q, got none", meshCapability)
	}

	// 2. Verify the discovered AgentCard contains the expected capability and a
	// valid signature from the publisher's peer key.
	cards, err := meshDiscoverCardsWithRetry(ctx, discovery, meshCapability)
	if err != nil {
		return fmt.Errorf("subscriber card discovery failed: %w", err)
	}
	if len(cards) == 0 {
		return fmt.Errorf("expected at least one AgentCard for capability %q", meshCapability)
	}
	validated := false
	for _, card := range cards {
		if card.PeerID != publisherID.String() {
			continue
		}
		if err := card.Verify(); err != nil {
			return fmt.Errorf("publisher card signature verification failed: %w", err)
		}
		validated = true
		break
	}
	if !validated {
		return fmt.Errorf("publisher card not found in discovered results")
	}

	// 3. Open a QUIC/MCP bridge stream to the publisher and do an echo round-trip.
	bridge, err := protocol.NewMCPBridge(node.Host(), meshAllowVerifier{}, meshEchoConnector{})
	if err != nil {
		return fmt.Errorf("subscriber bridge setup: %w", err)
	}
	if err := meshEchoRoundTrip(ctx, bridge, publisherID); err != nil {
		return fmt.Errorf("MCP echo round-trip failed: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Round-trip helper
// ---------------------------------------------------------------------------

func meshEchoRoundTrip(ctx context.Context, bridge *protocol.MCPBridge, target peer.ID) error {
	stream, err := bridge.Open(ctx, target, protocol.BridgeOpenRequest{
		BiscuitToken: "mesh-token",
		Amount:       1,
		Asset:        "sam-credit",
		Nonce:        "mesh-nonce",
		Capability:   meshCapability,
	})
	if err != nil {
		return fmt.Errorf("opening bridge stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	payload := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
	if _, err := stream.Write(payload); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, received); err != nil {
		return fmt.Errorf("reading echo response: %w", err)
	}
	if string(received) != string(payload) {
		return fmt.Errorf("echo mismatch: want %q, got %q", string(payload), string(received))
	}
	return nil
}

func meshConfigureNodePassport(ctx context.Context, node samnet.Node, subject string) error {
	passport, err := identity.IssuePassportBiscuit(ctx, identity.PassportIssueRequest{
		PeerID:       node.PeerID().String(),
		FederationID: "default",
		Subject:      subject,
	})
	if err != nil {
		return err
	}
	return identity.SetLocalPassport(node.Host(), "default", passport)
}

// ---------------------------------------------------------------------------
// Retry helpers (mesh-specific, same pattern as p2p_test.go)
// ---------------------------------------------------------------------------

func meshPublishWithRetry(ctx context.Context, pub *protocol.Publisher, card *protocol.AgentCard) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := pub.Publish(ctx, card); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			if last != nil { //nolint:staticcheck // last is assigned only on error in the loop
				return fmt.Errorf("publish did not converge: %w", last)
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func meshConnectWithRetry(ctx context.Context, node samnet.Node, pi peer.AddrInfo) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := node.Connect(ctx, pi); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			if last != nil { //nolint:staticcheck // last is assigned only on error in the loop
				return last
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func meshDiscoverAndConnectWithRetry(ctx context.Context, svc *protocol.DiscoveryService, cap string) ([]peer.ID, error) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		ids, err := svc.DiscoverAndConnect(ctx, cap)
		if len(ids) > 0 {
			return ids, nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ctx.Done():
			if last != nil {
				return nil, fmt.Errorf("no peers for capability %q: %w", cap, last)
			}
			return nil, fmt.Errorf("no peers for capability %q: %w", cap, ctx.Err())
		case <-ticker.C:
		}
	}
}

func meshDiscoverCardsWithRetry(ctx context.Context, svc *protocol.DiscoveryService, cap string) ([]*protocol.AgentCard, error) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		cards, err := svc.Discover(ctx, cap)
		if err == nil && len(cards) > 0 {
			return cards, nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ctx.Done():
			if last != nil {
				return nil, fmt.Errorf("card discovery for %q: %w", cap, last)
			}
			return nil, fmt.Errorf("no cards for capability %q: %w", cap, ctx.Err())
		case <-ticker.C:
		}
	}
}

// ---------------------------------------------------------------------------
// Node factory
// ---------------------------------------------------------------------------

func newMeshNode(port int, mode samnet.DHTMode, bootstrap []multiaddr.Multiaddr) (samnet.Node, error) {
	listen, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port))
	if err != nil {
		return nil, fmt.Errorf("building listen address: %w", err)
	}
	key, err := samnet.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating node key: %w", err)
	}
	return samnet.New(
		samnet.WithPrivateKey(key),
		samnet.WithListenAddrs(listen),
		samnet.WithBootstrapPeers(bootstrap...),
		samnet.WithDHTMode(mode),
	)
}

// ---------------------------------------------------------------------------
// Process management
// (roleProcess is defined in p2p_test.go; reuse it here)
// ---------------------------------------------------------------------------

func startMeshRoleProcess(t *testing.T, role, infoFile, ip string, port int) *roleProcess {
	t.Helper()
	proc := &roleProcess{}
	cmd := exec.Command(os.Args[0], "-test.run=TestMeshDiscovery$", "-test.v=true")
	cmd.Env = append(os.Environ(),
		meshHelperEnv+"=1",
		meshRoleEnv+"="+role,
		meshInfoEnv+"="+infoFile,
		meshIPEnv+"="+ip,
		meshPortEnv+"="+strconv.Itoa(port),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("creating %s stdin pipe: %v", role, err)
	}
	proc.stdin = stdin
	cmd.Stdout = &proc.stdout
	cmd.Stderr = &proc.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s process: %v", role, err)
	}
	proc.cmd = cmd
	return proc
}

func stopMeshRoleProcess(proc *roleProcess) {
	if proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return
	}
	_ = proc.stdin.Close()
	_ = proc.cmd.Process.Kill()
	_, _ = proc.cmd.Process.Wait()
}

func waitMeshRoleExit(t *testing.T, proc *roleProcess, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- proc.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("role process wait failed: %v\nstdout:\n%s\nstderr:\n%s",
				err, proc.stdout.String(), proc.stderr.String())
		}
	case <-time.After(timeout):
		t.Fatalf("role process timed out\nstdout:\n%s\nstderr:\n%s",
			proc.stdout.String(), proc.stderr.String())
	}
}

// ---------------------------------------------------------------------------
// Network namespace helpers
// ---------------------------------------------------------------------------

func configureMeshVethPair(t *testing.T, publisherPID, subscriberPID int) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "meshveth-p"},
		PeerName:  "meshveth-s",
	}); err != nil {
		t.Fatalf("creating mesh veth pair: %v", err)
	}

	pubLink, err := netlink.LinkByName("meshveth-p")
	if err != nil {
		t.Fatalf("finding publisher veth: %v", err)
	}
	subLink, err := netlink.LinkByName("meshveth-s")
	if err != nil {
		t.Fatalf("finding subscriber veth: %v", err)
	}

	if err := netlink.LinkSetNsPid(pubLink, publisherPID); err != nil {
		t.Fatalf("moving publisher veth to pid %d: %v", publisherPID, err)
	}
	if err := netlink.LinkSetNsPid(subLink, subscriberPID); err != nil {
		t.Fatalf("moving subscriber veth to pid %d: %v", subscriberPID, err)
	}

	configureMeshLinkInNetNS(t, publisherPID, "meshveth-p", meshPublisherIP+"/24")
	configureMeshLinkInNetNS(t, subscriberPID, "meshveth-s", meshSubscriberIP+"/24")
}

func configureMeshLinkInNetNS(t *testing.T, pid int, linkName, cidr string) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalNS, err := netns.Get()
	if err != nil {
		t.Fatalf("getting current netns: %v", err)
	}
	defer func() { _ = originalNS.Close() }()

	targetNS, err := netns.GetFromPid(pid)
	if err != nil {
		t.Fatalf("getting netns for pid %d: %v", pid, err)
	}
	defer func() { _ = targetNS.Close() }()

	if err := netns.Set(targetNS); err != nil {
		t.Fatalf("entering netns for pid %d: %v", pid, err)
	}
	defer func() {
		if err := netns.Set(originalNS); err != nil {
			t.Fatalf("restoring original netns: %v", err)
		}
	}()

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("getting loopback in netns pid %d: %v", pid, err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bringing loopback up in netns pid %d: %v", pid, err)
	}

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		t.Fatalf("getting link %s in netns pid %d: %v", linkName, pid, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parsing cidr %s: %v", cidr, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("assigning addr %s to %s in pid %d: %v", cidr, linkName, pid, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bringing link %s up in netns pid %d: %v", linkName, pid, err)
	}
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

func writeMeshPeerInfo(path string, info meshPeerInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating mesh info file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return json.NewEncoder(f).Encode(info)
}

func waitMeshPeerInfo(ctx context.Context, path string) (meshPeerInfo, error) {
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var info meshPeerInfo
			if unmarshalErr := json.Unmarshal(data, &info); unmarshalErr != nil {
				return meshPeerInfo{}, fmt.Errorf("decoding mesh info: %w", unmarshalErr)
			}
			return info, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return meshPeerInfo{}, fmt.Errorf("reading mesh info: %w", err)
		}
		select {
		case <-ctx.Done():
			return meshPeerInfo{}, fmt.Errorf("waiting for mesh info file: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitForMeshInfoFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func parseMeshPort() (int, error) {
	raw := os.Getenv(meshPortEnv)
	if raw == "" {
		return 0, fmt.Errorf("missing %s", meshPortEnv)
	}
	p, err := strconv.Atoi(raw)
	if err != nil || p <= 0 {
		return 0, fmt.Errorf("invalid mesh port %q", raw)
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// Stub verifier — accepts any micropayment token (mesh test has no real Biscuit)
// ---------------------------------------------------------------------------

type meshAllowVerifier struct{}

func (meshAllowVerifier) Verify(_ context.Context, _ economy.VerifyRequest) (*economy.VerifyDecision, error) {
	return &economy.VerifyDecision{Subject: "peer:mesh"}, nil
}

// ---------------------------------------------------------------------------
// Stub MCP connector — loopback echo server
// ---------------------------------------------------------------------------

type meshEchoConnector struct{}

func (meshEchoConnector) Open(context.Context) (mcp.Transport, error) {
	a, b := net.Pipe()
	go func() {
		defer func() { _ = b.Close() }()
		buf := make([]byte, 32*1024)
		for {
			n, err := b.Read(buf)
			if n > 0 {
				if _, werr := b.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return &mcp.IOTransport{Reader: a, Writer: a}, nil
}
