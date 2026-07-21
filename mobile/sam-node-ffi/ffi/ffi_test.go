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

package ffi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

func TestMobileFFILifecycle(t *testing.T) {
	// 1. Setup Mock Hub
	hubHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hubHost.Close() }()

	hubDHT, err := dht.New(hubHost, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hubDHT.Close() }()

	// Generate key-pair for Mock Control Plane signing
	cpPubKey, cpPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hubHost.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		println("--- MOCK HUB: received auth stream connection")
		defer func() { _ = s.Close() }()

		biscuitBytes := mintMockBiscuit(t, hubHost.ID().String(), cpPrivKey, api.RoleRouter)

		resp := &api.AuthResponse{
			Success: true,
			Biscuit: biscuitBytes,
		}
		data, _ := proto.Marshal(resp)
		writer := msgio.NewVarintWriter(s)
		if err := writer.WriteMsg(data); err != nil {
			println("--- MOCK HUB: failed to write AuthResponse:", err.Error())
			return
		}
		println("--- MOCK HUB: wrote AuthResponse success with valid biscuit")
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req api.EnrollRequest
		_ = proto.Unmarshal(body, &req)

		biscuitBytes := mintMockBiscuit(t, req.PeerId, cpPrivKey, api.RoleNode)
		resp := &api.EnrollResponse{
			BiscuitToken: biscuitBytes,
			HubPublicKey: cpPubKey,
			HubAddresses: []string{hubHost.Addrs()[0].String() + "/p2p/" + hubHost.ID().String()},
		}
		data, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := &api.HubInfoResponse{
			OidcIssuer: "http://mock-issuer",
			ClientId:   "mock-client",
			Audience:   "mock-audience",
		}
		data, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(data)
	})

	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	// 2. Mobile Enrollment
	tmpDir := t.TempDir()
	err = EnrollNode(tmpDir, httpServer.URL, "dummy-jwt", true)
	if err != nil {
		t.Fatalf("EnrollNode failed: %v", err)
	}

	// 3. Mobile Node Start
	cfg := MobileConfig{
		DataDir:       tmpDir,
		HubURL:        httpServer.URL,
		MeshID:        "test-mesh",
		BindAddr:      "127.0.0.1:0", // random free port
		ApiToken:      "test-token",
		AllowLoopback: true,
	}
	cfgBytes, _ := json.Marshal(cfg)

	err = StartNode(string(cfgBytes))
	if err != nil {
		t.Fatalf("StartNode failed: %v", err)
	}

	if GetNodeID() == "" || GetNodeID() == "unauthenticated" {
		t.Fatalf("Expected valid peer ID, got %q", GetNodeID())
	}

	// Stop Node
	err = StopNode()
	if err != nil {
		t.Fatalf("StopNode failed: %v", err)
	}
}

func mintMockBiscuit(t *testing.T, peerID string, priv ed25519.PrivateKey, role string) []byte {
	builder := biscuit.NewBuilder(priv)
	if err := builder.AddAuthorityFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "node",
			IDs:  []biscuit.Term{biscuit.String(peerID)},
		},
	}); err != nil {
		t.Fatalf("failed to add node fact: %v", err)
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactRole,
			IDs:  []biscuit.Term{biscuit.String(role)},
		},
	}); err != nil {
		t.Fatalf("failed to add role fact: %v", err)
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactExpiration,
			IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
		},
	}); err != nil {
		t.Fatalf("failed to add expiration fact: %v", err)
	}
	b, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build biscuit: %v", err)
	}
	biscuitBytes, err := b.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize biscuit: %v", err)
	}
	return biscuitBytes
}
