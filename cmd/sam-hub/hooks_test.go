package main

import (
	"testing"

	"time"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/host"
)

type mockConn struct {
	network.Conn
	peer peer.ID
}

func (m mockConn) RemotePeer() peer.ID { return m.peer }

type mockNetwork struct {
	network.Network
	conns int
}

func (m *mockNetwork) ConnsToPeer(p peer.ID) []network.Conn {
	conns := make([]network.Conn, m.conns)
	return conns
}

type mockHost struct {
	host.Host
	net *mockNetwork
}

func (m *mockHost) Network() network.Network { return m.net }

func TestNotifier_Disconnected(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	remotePeer := peer.ID("peer1")

	mockNet := &mockNetwork{conns: 1} // Initial state: 1 connection remains after one drops (so 2 total originally)
	mockH := &mockHost{net: mockNet}

	hub := &Hub{
		Host:    mockH,
		KeyRing: kr,
		gater:   newHubConnGate(),
	}

	notifier := &notifier{
		hub: hub,
	}

	// Simulate authentication
	hub.gater.mu.Lock()
	hub.gater.authenticated[remotePeer] = true
	hub.gater.mu.Unlock()

	conn := mockConn{peer: remotePeer}

	// 1. One connection drops, but another remains active (mockNet.conns = 1)
	notifier.Disconnected(mockNet, conn)

	hub.gater.mu.RLock()
	authed := hub.gater.authenticated[remotePeer]
	hub.gater.mu.RUnlock()

	if !authed {
		t.Fatal("Expected peer to remain authenticated because another connection is active")
	}

	// 2. The last connection drops (mockNet.conns = 0)
	mockNet.conns = 0
	notifier.Disconnected(mockNet, conn)

	hub.gater.mu.RLock()
	authed = hub.gater.authenticated[remotePeer]
	hub.gater.mu.RUnlock()

	if authed {
		t.Fatal("Expected peer to be removed from authenticated map after last connection dropped")
	}
}
