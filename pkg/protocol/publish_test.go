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

package protocol_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"sam/pkg/protocol"
)

type fakePublisherNode struct {
	peerID    peer.ID
	announced []string
	stored    map[string][]byte
	errOn     string
}

func (f *fakePublisherNode) Announce(_ context.Context, capability string) error {
	f.announced = append(f.announced, capability)
	if f.errOn != "" && f.errOn == capability {
		return context.DeadlineExceeded
	}
	return nil
}

func (f *fakePublisherNode) PeerID() peer.ID {
	return f.peerID
}

func (f *fakePublisherNode) PutValue(_ context.Context, key string, value []byte) error {
	if f.stored == nil {
		f.stored = map[string][]byte{}
	}
	f.stored[key] = append([]byte(nil), value...)
	return nil
}

func TestPublisherPublishesPeerAndCapabilityNamespaces(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	card, err := protocol.NewAgentCard(pid, []string{"inference", "search"}, nil, priv)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}

	node := &fakePublisherNode{peerID: pid}
	publisher, err := protocol.NewPublisher(node)
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}

	if err := publisher.Publish(context.Background(), card); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	want := []string{
		protocol.AgentPeerNamespace(pid.String()),
		protocol.AgentCapabilityNamespace("inference"),
		protocol.AgentCapabilityNamespace("search"),
	}
	if !reflect.DeepEqual(node.announced, want) {
		t.Fatalf("announced = %#v, want %#v", node.announced, want)
	}
	if len(node.stored) != 3 {
		t.Fatalf("stored values = %d, want 3 (peer key + 2 capabilities)", len(node.stored))
	}
}

func TestPublisherRejectsPeerMismatch(t *testing.T) {
	privA, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	pidA, err := peer.IDFromPrivateKey(privA)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	privB, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	pidB, err := peer.IDFromPrivateKey(privB)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	card, err := protocol.NewAgentCard(pidA, []string{"inference"}, nil, privA)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}

	publisher, err := protocol.NewPublisher(&fakePublisherNode{peerID: pidB})
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}

	if err := publisher.Publish(context.Background(), card); err == nil {
		t.Fatal("Publish() should fail on peer ID mismatch")
	}
}

func TestAgentNamespaceHelpers(t *testing.T) {
	tests := []struct {
		name       string
		capability string
		want       string
	}{
		{name: "trim and lower", capability: "  Search ", want: "/sam/v1/agents/capability/search"},
		{name: "spaces to dash", capability: "web crawl", want: "/sam/v1/agents/capability/web-crawl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protocol.AgentCapabilityNamespace(tt.capability); got != tt.want {
				t.Fatalf("AgentCapabilityNamespace(%q) = %q, want %q", tt.capability, got, tt.want)
			}
		})
	}
}
