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
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func newTestIdentity(t *testing.T) (crypto.PrivKey, peer.ID) {
	t.Helper()
	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}
	return priv, pid
}

func TestServiceAnnounceSignVerifyRoundTrip(t *testing.T) {
	priv, pid := newTestIdentity(t)
	info := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "github-tools"}
	a := buildServiceAnnounce(info, pid, []string{"/ip4/127.0.0.1/tcp/4001"}, time.UnixMilli(1_700_000_000_000), serviceAnnounceTTL)
	if a.PeerId != pid.String() {
		t.Fatalf("peer id not set: %q", a.PeerId)
	}
	if err := signServiceAnnounce(priv, a); err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := verifyServiceAnnounce(a)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
}

func TestServiceAnnounceTamperFails(t *testing.T) {
	priv, pid := newTestIdentity(t)
	info := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "a"}
	a := buildServiceAnnounce(info, pid, nil, time.UnixMilli(1), time.Minute)
	if err := signServiceAnnounce(priv, a); err != nil {
		t.Fatalf("sign: %v", err)
	}
	a.Name = "b" // tamper after signing
	ok, _ := verifyServiceAnnounce(a)
	if ok {
		t.Fatal("expected verification to fail after tamper")
	}
}

func TestServiceAnnounceWrongPeerFails(t *testing.T) {
	priv, _ := newTestIdentity(t)
	_, otherPID := newTestIdentity(t)
	info := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "a"}
	a := buildServiceAnnounce(info, otherPID, nil, time.UnixMilli(1), time.Minute) // claims other peer
	if err := signServiceAnnounce(priv, a); err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, _ := verifyServiceAnnounce(a) // verifies against otherPID's key, not priv
	if ok {
		t.Fatal("expected verification to fail for mismatched peer id")
	}
}
