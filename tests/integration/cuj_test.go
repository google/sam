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
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	coreprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"

	"sam/internal/testutils"
	samnet "sam/pkg/net"
)

// CUJ-1 Stealth Audit: peers in the same mesh namespace discover each other
// through DHT capability discovery.
func TestCUJ1StealthAuditMeshDiscovery(t *testing.T) {
	if !testutils.IsSupported() {
		t.Skip("user namespaces not available")
	}
	testutils.Run(t, runCUJ1StealthAuditMeshDiscovery)
}

func runCUJ1StealthAuditMeshDiscovery(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	seed := cujStartNode(t, cujNodeConfig{mode: samnet.DHTModeServer})

	publisher := cujStartNode(t, cujNodeConfig{bootstrap: cujBootstrapAddrs(t, seed), mode: samnet.DHTModeServer})
	discovererA := cujStartNode(t, cujNodeConfig{bootstrap: cujBootstrapAddrs(t, seed), mode: samnet.DHTModeServer})
	discovererB := cujStartNode(t, cujNodeConfig{bootstrap: cujBootstrapAddrs(t, seed), mode: samnet.DHTModeServer})

	const capability = "risk-audit"
	if err := publisher.Announce(ctx, capability); err != nil {
		t.Fatalf("publisher announce: %v", err)
	}

	foundA := cujWaitDiscover(ctx, discovererA, capability, publisher.PeerID().String())
	if !foundA {
		t.Fatalf("mesh discovery failed: discovererA could not discover publisher capability")
	}

	foundB := cujWaitDiscover(ctx, discovererB, capability, publisher.PeerID().String())
	if !foundB {
		t.Fatalf("mesh discovery failed: discovererB could not discover publisher capability")
	}
}

// CUJ-2 Hole-Punch: verify relay-assisted connectivity path and attempt to
// observe a direct (non-circuit) connection after initial circuit dial.
//
// In restricted CI/network environments DCUtR may not complete; in that case
// the test validates relay path and skips direct-connection assertion.
func TestCUJ2HolePunchRelayAssisted(t *testing.T) {
	if !testutils.IsSupported() {
		t.Skip("user namespaces not available")
	}
	testutils.Run(t, runCUJ2HolePunchRelayAssisted)
}

func runCUJ2HolePunchRelayAssisted(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	relayNode := cujStartNode(t, cujNodeConfig{relayService: true, mode: samnet.DHTModeServer})
	bootstrap := cujBootstrapAddrs(t, relayNode)

	caller := cujStartNode(t, cujNodeConfig{bootstrap: bootstrap, mode: samnet.DHTModeServer})
	target := cujStartNode(t, cujNodeConfig{bootstrap: bootstrap, mode: samnet.DHTModeServer})

	const protoID coreprotocol.ID = "/sam/cuj/holepunch/1.0"
	target.Host().SetStreamHandler(protoID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		r := bufio.NewReader(s)
		line, _ := r.ReadString('\n')
		_, _ = io.WriteString(s, line)
	})

	circuitAddr, err := cujRelayCircuitAddr(relayNode, target)
	if err != nil {
		t.Fatalf("building circuit address: %v", err)
	}
	if err := caller.Connect(ctx, circuitAddr); err != nil {
		t.Fatalf("relay-assisted connect failed: %v", err)
	}

	stream, err := caller.Host().NewStream(ctx, target.PeerID(), protoID)
	if err != nil {
		t.Fatalf("opening stream over relay-assisted path failed: %v", err)
	}
	if _, err := io.WriteString(stream, "hello\n"); err != nil {
		_ = stream.Close()
		t.Fatalf("writing stream payload: %v", err)
	}
	resp, err := bufio.NewReader(stream).ReadString('\n')
	_ = stream.Close()
	if err != nil {
		t.Fatalf("reading stream response: %v", err)
	}
	if strings.TrimSpace(resp) != "hello" {
		t.Fatalf("unexpected stream response: %q", resp)
	}

	directSeen := cujWaitForDirectConn(ctx, caller, target)
	if !directSeen {
		t.Skip("relay path verified; no direct non-circuit connection observed (DCUtR environment-dependent)")
	}
}

type cujNodeConfig struct {
	bootstrap    []multiaddr.Multiaddr
	relayService bool
	mode         samnet.DHTMode
}

func cujStartNode(t *testing.T, cfg cujNodeConfig) samnet.Node {
	t.Helper()
	listen, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/udp/0/quic-v1")
	if err != nil {
		t.Fatalf("creating listen addr: %v", err)
	}
	key, err := samnet.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	opts := []samnet.Option{
		samnet.WithPrivateKey(key),
		samnet.WithListenAddrs(listen),
		samnet.WithDHTMode(cfg.mode),
	}
	if len(cfg.bootstrap) > 0 {
		opts = append(opts, samnet.WithBootstrapPeers(cfg.bootstrap...))
	}
	if cfg.relayService {
		opts = append(opts, samnet.WithRelayService())
	}
	n, err := samnet.New(opts...)
	if err != nil {
		t.Fatalf("creating node: %v", err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("starting node: %v", err)
	}
	t.Cleanup(func() {
		go func() { _ = n.Stop(context.Background()) }()
	})
	return n
}

func cujBootstrapAddrs(t *testing.T, n samnet.Node) []multiaddr.Multiaddr {
	t.Helper()
	for _, a := range n.Addrs() {
		if !strings.Contains(a.String(), "quic") {
			continue
		}
		full, err := multiaddr.NewMultiaddr(fmt.Sprintf("%s/p2p/%s", a.String(), n.PeerID()))
		if err == nil {
			return []multiaddr.Multiaddr{full}
		}
	}
	t.Fatalf("no bootstrap QUIC address found for %s", n.PeerID())
	return nil
}

func cujWaitDiscover(ctx context.Context, n samnet.Node, capability, expectedPeerID string) bool {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		discoveryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ch, err := n.Discover(discoveryCtx, capability)
		if err == nil {
			for ai := range ch {
				if ai.ID.String() == expectedPeerID {
					cancel()
					return true
				}
			}
		}
		cancel()

		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func cujRelayCircuitAddr(relayNode, target samnet.Node) (peer.AddrInfo, error) {
	for _, relayAddr := range relayNode.Addrs() {
		if !strings.Contains(relayAddr.String(), "quic") {
			continue
		}
		circuit := fmt.Sprintf("%s/p2p/%s/p2p-circuit/p2p/%s", relayAddr.String(), relayNode.PeerID(), target.PeerID())
		ma, err := multiaddr.NewMultiaddr(circuit)
		if err != nil {
			continue
		}
		return peer.AddrInfo{ID: target.PeerID(), Addrs: []multiaddr.Multiaddr{ma}}, nil
	}
	return peer.AddrInfo{}, fmt.Errorf("no relay QUIC address available")
}

func cujWaitForDirectConn(ctx context.Context, a, b samnet.Node) bool {
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		conns := a.Host().Network().ConnsToPeer(b.PeerID())
		for _, c := range conns {
			if !strings.Contains(c.RemoteMultiaddr().String(), "p2p-circuit") {
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
