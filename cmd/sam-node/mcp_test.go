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
	"net/http"
	"net/http/httptest"
	"testing"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peerstore"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/multiformats/go-multiaddr"
)

func TestMCPHandler_HTTP(t *testing.T) {
	// Setup a dummy node
	node := &SamNode{}
	handler := NewMCPHandler(node)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	client := &http.Client{}

	// Test GET on root (should be 404 now)
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status NotFound on root, got %d", resp.StatusCode)
	}

	// Test GET on /mcp/events
	req2, err := http.NewRequest("GET", ts.URL+"/mcp/events", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status OK or BadRequest on /mcp/events, got %d", resp2.StatusCode)
	}
}

func TestResolveRelayAddresses(t *testing.T) {
	ctx := context.Background()
	mn := mocknet.New()

	// Create local host
	localHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}

	// Create a real DHT bound to the mock host
	kdht, err := dht.New(ctx, localHost, dht.Mode(dht.ModeServer))
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Host: localHost,
		DHT:  kdht,
	}

	// Create relay host
	relayHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	relayID := relayHost.ID()

	// Add relay direct IP to DHT peerstore
	relayDirectAddr, _ := multiaddr.NewMultiaddr("/ip4/10.0.0.1/tcp/4501")
	localHost.Peerstore().AddAddr(relayID, relayDirectAddr, peerstore.PermanentAddrTTL)
	relayHost.Peerstore().AddAddr(relayID, relayDirectAddr, peerstore.PermanentAddrTTL)

	// Create DHT for relay
	relayDHT, err := dht.New(ctx, relayHost, dht.Mode(dht.ModeServer))
	if err != nil {
		t.Fatal(err)
	}

	mn.LinkAll()
	mn.ConnectAllButSelf()

	// Wait for DHT
	kdht.RoutingTable().TryAddPeer(relayID, true, true)
	relayDHT.RoutingTable().TryAddPeer(localHost.ID(), true, true)

	// Create a target node behind the relay
	targetHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	targetID := targetHost.ID()

	// Add a dns-based circuit address for the target node to the local host's peerstore
	circuitAddrStr := fmt.Sprintf("/dns4/hub.com/tcp/4501/p2p/%s/p2p-circuit", relayID.String())
	circuitAddr, _ := multiaddr.NewMultiaddr(circuitAddrStr)
	localHost.Peerstore().AddAddr(targetID, circuitAddr, peerstore.PermanentAddrTTL)

	// Run the function
	node.resolveRelayAddresses(ctx, targetID)

	// Verify that the direct IP circuit address was added to the target's peerstore
	addrs := localHost.Peerstore().Addrs(targetID)
	foundDirect := false
	expectedDirectAddrStr := fmt.Sprintf("/ip4/10.0.0.1/tcp/4501/p2p/%s/p2p-circuit", relayID.String())

	for _, addr := range addrs {
		if addr.String() == expectedDirectAddrStr {
			foundDirect = true
			break
		}
	}

	if !foundDirect {
		t.Errorf("Expected address %s not found in peerstore. Got: %v", expectedDirectAddrStr, addrs)
	}
}
