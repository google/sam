package main
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

func TestSAMReservedSearchReturnsPublishedWriterCard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpHome, ".config"))

	nodeB, err := newProxyReservedNode(0, nil)
	if err != nil {
		t.Fatalf("creating proxy/search node: %v", err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatalf("starting proxy/search node: %v", err)
	}
	defer func() { _ = nodeB.Stop(context.Background()) }()

	bootstrap := []multiaddr.Multiaddr{nodeB.Addrs()[0].Encapsulate(multiaddr.StringCast("/p2p/" + nodeB.PeerID().String()))}
	nodeA, err := newProxyReservedNode(0, bootstrap)
	if err != nil {
		t.Fatalf("creating publisher node: %v", err)
	}
	if err := nodeA.Start(ctx); err != nil {
		t.Fatalf("starting publisher node: %v", err)
	}
	defer func() { _ = nodeA.Stop(context.Background()) }()

	if err := connectProxyReservedWithRetry(ctx, nodeA, peer.AddrInfo{ID: nodeB.PeerID(), Addrs: nodeB.Addrs()}); err != nil {
		t.Fatalf("connecting publisher to search node: %v", err)
	}
	if err := connectProxyReservedWithRetry(ctx, nodeB, peer.AddrInfo{ID: nodeA.PeerID(), Addrs: nodeA.Addrs()}); err != nil {
		t.Fatalf("connecting search node to publisher: %v", err)
	}

	priv := nodeA.Host().Peerstore().PrivKey(nodeA.PeerID())
	if priv == nil {
		t.Fatalf("publisher private key missing")
	}
	card, err := protocol.NewAgentCard(nodeA.PeerID(), []string{"writer"}, []protocol.MCPResource{{Name: "writer", Kind: "tool", Endpoint: "mcp://writer"}}, priv)
	if err != nil {
		t.Fatalf("creating writer card: %v", err)
	}
	if err := attachNodeVouch(card, nodeA.PeerID().String(), priv); err != nil {
		t.Fatalf("attaching card vouch: %v", err)
	}
	pub, err := protocol.NewPublisher(nodeA)
	if err != nil {
		t.Fatalf("creating publisher: %v", err)
	}
	if err := publishProxyReservedWithRetry(ctx, pub, card); err != nil {
		t.Fatalf("publishing writer card: %v", err)
	}

	cfg := &runConfig{proxyTimeout: 3 * time.Second, federation: "default"}

	deadline := time.Now().Add(12 * time.Second)
	for {
		req := httptest.NewRequest(http.MethodGet, "/.sam/search?skill=writer", nil)
		rr := httptest.NewRecorder()
		handleSAMReserved(rr, req, nodeB, cfg)

		if rr.Code == http.StatusOK {
			var cards []*protocol.AgentCard
			if err := json.Unmarshal(rr.Body.Bytes(), &cards); err != nil {
				t.Fatalf("decoding search response: %v", err)
			}
			for _, got := range cards {
				if got != nil && got.PeerID == nodeA.PeerID().String() {
					if got.Vouch == nil || got.Vouch.Signature == "" {
						t.Fatalf("expected signed vouch in search response for %s", got.PeerID)
					}
					return
				}
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("writer card not discovered in /.sam/search response before timeout")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func newProxyReservedNode(port int, bootstrap []multiaddr.Multiaddr) (samnet.Node, error) {
	listen, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1", port))
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
		samnet.WithDHTMode(samnet.DHTModeServer),
	)
}

func connectProxyReservedWithRetry(ctx context.Context, node samnet.Node, pi peer.AddrInfo) error {
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
			if last != nil {
				return last
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func publishProxyReservedWithRetry(ctx context.Context, pub *protocol.Publisher, card *protocol.AgentCard) error {
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
			if last != nil {
				return last
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
