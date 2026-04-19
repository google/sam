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

package samnet_test

import (
	"context"
	"testing"
	"time"

	samnet "sam/pkg/net"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestGenerateKey(t *testing.T) {
	k1, err := samnet.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if k1 == nil {
		t.Fatal("GenerateKey() returned nil key")
	}

	// Verify the key produces a valid peer ID.
	id1, err := peer.IDFromPrivateKey(k1)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}
	if id1 == "" {
		t.Fatal("derived empty peer ID")
	}

	// Two keys must produce distinct identities.
	k2, err := samnet.GenerateKey()
	if err != nil {
		t.Fatalf("second GenerateKey() error = %v", err)
	}
	id2, _ := peer.IDFromPrivateKey(k2)
	if id1 == id2 {
		t.Error("two generated keys produced the same peer ID")
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		opts    []samnet.Option
		wantErr bool
	}{
		{
			name: "defaults",
			opts: nil,
		},
		{
			name: "custom key",
			opts: func() []samnet.Option {
				k, _ := samnet.GenerateKey()
				return []samnet.Option{samnet.WithPrivateKey(k)}
			}(),
		},
		{
			name: "custom user agent",
			opts: []samnet.Option{samnet.WithUserAgent("test/1.0")},
		},
		{
			name: "server DHT mode",
			opts: []samnet.Option{samnet.WithDHTMode(samnet.DHTModeServer)},
		},
		{
			name: "with relay service",
			opts: []samnet.Option{samnet.WithRelayService()},
		},
		{
			name:    "empty listen addrs rejected",
			opts:    []samnet.Option{samnet.WithListenAddrs()},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := samnet.New(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && n == nil {
				t.Fatal("New() returned nil node")
			}
		})
	}
}

func TestNodeStartStop(t *testing.T) {
	quic, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/udp/0/quic-v1")
	n, err := samnet.New(
		samnet.WithListenAddrs(quic),
		samnet.WithDHTMode(samnet.DHTModeServer),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := n.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if n.PeerID() == "" {
		t.Error("PeerID() is empty after Start")
	}
	if len(n.Addrs()) == 0 {
		t.Error("Addrs() is empty after Start")
	}
	if n.Host() == nil {
		t.Error("Host() is nil after Start")
	}
	if n.DHT() == nil {
		t.Error("DHT() is nil after Start")
	}

	// Double start must error.
	if err := n.Start(ctx); err == nil {
		t.Error("second Start() should return error")
	}

	if err := n.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	// Double stop must be safe (idempotent).
	if err := n.Stop(ctx); err != nil {
		t.Fatalf("second Stop() should not error, got %v", err)
	}
}

func TestDHTRouting(t *testing.T) {
	tests := []struct {
		name       string
		capability string
		announce   bool
		wantFound  bool
	}{
		{
			name:       "announced capability is discoverable",
			capability: "llm/gpt4",
			announce:   true,
			wantFound:  true,
		},
		{
			name:       "unannounced capability returns no peers",
			capability: "llm/nonexistent",
			announce:   false,
			wantFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			quic, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/udp/0/quic-v1")

			// Create and start the provider node.
			provider, err := samnet.New(
				samnet.WithListenAddrs(quic),
				samnet.WithDHTMode(samnet.DHTModeServer),
			)
			if err != nil {
				t.Fatalf("creating provider: %v", err)
			}
			if err := provider.Start(ctx); err != nil {
				t.Fatalf("starting provider: %v", err)
			}
			defer func() { _ = provider.Stop(ctx) }()

			// Create and start the consumer node.
			consumer, err := samnet.New(
				samnet.WithListenAddrs(quic),
				samnet.WithDHTMode(samnet.DHTModeServer),
			)
			if err != nil {
				t.Fatalf("creating consumer: %v", err)
			}
			if err := consumer.Start(ctx); err != nil {
				t.Fatalf("starting consumer: %v", err)
			}
			defer func() { _ = consumer.Stop(ctx) }()

			// Connect the two nodes so the DHT can route between them.
			providerInfo := peer.AddrInfo{
				ID:    provider.PeerID(),
				Addrs: provider.Addrs(),
			}
			if err := consumer.Connect(ctx, providerInfo); err != nil {
				t.Fatalf("connecting consumer to provider: %v", err)
			}

			// Wait for DHT routing tables to populate after connection.
			// The DHT processes connection events asynchronously.
			waitForDHT(t, ctx, provider)
			waitForDHT(t, ctx, consumer)

			// Announce if the test case requires it.
			if tt.announce {
				if err := provider.Announce(ctx, tt.capability); err != nil {
					t.Fatalf("Announce() error = %v", err)
				}
			}

			// Discover with a bounded timeout.
			discoverCtx, discoverCancel := context.WithTimeout(ctx, 5*time.Second)
			defer discoverCancel()

			ch, err := consumer.Discover(discoverCtx, tt.capability)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			var found bool
			for pi := range ch {
				if pi.ID == provider.PeerID() {
					found = true
					break
				}
			}

			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
		})
	}
}

// waitForDHT polls until the node's DHT routing table has at least one peer,
// or the context expires.
func waitForDHT(t *testing.T, ctx context.Context, n samnet.Node) {
	t.Helper()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(10 * time.Second)
	for {
		if n.DHT().RoutingTable().Size() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("DHT routing table empty after 10s (peer %s)", n.PeerID())
		case <-ctx.Done():
			t.Fatal("context cancelled waiting for DHT peers")
		case <-ticker.C:
		}
	}
}
