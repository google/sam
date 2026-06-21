package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/sam/api"
	"github.com/multiformats/go-multiaddr"
)

type mockHubConnectionManager struct {
	connected      bool
	peerID         string
	hubConfigErr   error
	storedAddrs    []string
	hubURLErr      error
	hubURL         string
	discoverErr    error
	discoverResp   *api.HubInfoResponse
	connectP2PErr  error
	connectHTTPReq bool
	connectHTTPErr error
	saveConfigErr  error
}

func (m *mockHubConnectionManager) IsConnected() bool {
	return m.connected
}

func (m *mockHubConnectionManager) HubPeerIDString() string {
	return m.peerID
}

func (m *mockHubConnectionManager) LoadHubConfig() ([]byte, []string, error) {
	return nil, m.storedAddrs, m.hubConfigErr
}

func (m *mockHubConnectionManager) ConnectAndAuthWithHub(ctx context.Context, addr multiaddr.Multiaddr) error {
	if m.connectHTTPReq {
		return m.connectHTTPErr
	}
	return m.connectP2PErr
}

func (m *mockHubConnectionManager) LoadHubURL() (string, error) {
	return m.hubURL, m.hubURLErr
}

func (m *mockHubConnectionManager) DiscoverHubInfo(ctx context.Context, url string) (*api.HubInfoResponse, error) {
	return m.discoverResp, m.discoverErr
}

func (m *mockHubConnectionManager) SaveHubConfig(pubKey []byte, addrs []string) error {
	return m.saveConfigErr
}

func (m *mockHubConnectionManager) UpdateRelays(addrs []multiaddr.Multiaddr) {}

func TestCheckHubConnection(t *testing.T) {
	cases := []struct {
		name       string
		mgr        *mockHubConnectionManager
		wantStable bool
		wantReconn bool
	}{
		{
			name: "already connected",
			mgr: &mockHubConnectionManager{
				connected: true,
			},
			wantStable: true,
			wantReconn: false,
		},
		{
			name: "disconnected, reconnects via P2P",
			mgr: &mockHubConnectionManager{
				connected:     false,
				storedAddrs:   []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr: nil,
			},
			wantStable: false,
			wantReconn: true,
		},
		{
			name: "disconnected, P2P fails, reconnects via HTTP",
			mgr: &mockHubConnectionManager{
				connected:     false,
				storedAddrs:   []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr: errors.New("p2p failed"),
				hubURL:        "https://hub.example.com",
				discoverResp: &api.HubInfoResponse{
					HubAddresses: []string{"/ip4/127.0.0.1/tcp/4002"},
				},
				connectHTTPReq: true,
				connectHTTPErr: nil,
			},
			wantStable: false,
			wantReconn: true,
		},
		{
			name: "disconnected, all fail",
			mgr: &mockHubConnectionManager{
				connected:     false,
				storedAddrs:   []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr: errors.New("p2p failed"),
				hubURL:        "https://hub.example.com",
				discoverResp: &api.HubInfoResponse{
					HubAddresses: []string{"/ip4/127.0.0.1/tcp/4002"},
				},
				connectHTTPReq: true,
				connectHTTPErr: errors.New("http fallback connect failed"),
			},
			wantStable: false,
			wantReconn: false,
		},
		{
			name: "disconnected, HTTP discovery fails",
			mgr: &mockHubConnectionManager{
				connected:     false,
				storedAddrs:   []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr: errors.New("p2p failed"),
				hubURL:        "https://hub.example.com",
				discoverErr:   errors.New("discovery failed"),
			},
			wantStable: false,
			wantReconn: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stable, reconnected := checkHubConnection(context.Background(), tc.mgr)
			if stable != tc.wantStable {
				t.Errorf("expected stable %v, got %v", tc.wantStable, stable)
			}
			if reconnected != tc.wantReconn {
				t.Errorf("expected reconnected %v, got %v", tc.wantReconn, reconnected)
			}
		})
	}
}
