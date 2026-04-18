package protocol_test

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

type fakeDiscoveryNode struct {
	host       host.Host
	peerID     peer.ID
	discoverCh chan peer.AddrInfo
	dhtValues  map[string][]byte
}

func (f *fakeDiscoveryNode) Start(context.Context) error { return nil }
func (f *fakeDiscoveryNode) Stop(context.Context) error  { return nil }
func (f *fakeDiscoveryNode) Host() host.Host             { return f.host }
func (f *fakeDiscoveryNode) DHT() *dht.IpfsDHT           { return nil }
func (f *fakeDiscoveryNode) PeerID() peer.ID             { return f.peerID }
func (f *fakeDiscoveryNode) Addrs() []multiaddr.Multiaddr {
	return f.host.Addrs()
}
func (f *fakeDiscoveryNode) Announce(context.Context, string) error { return nil }
func (f *fakeDiscoveryNode) PutValue(_ context.Context, key string, value []byte) error {
	if f.dhtValues == nil {
		f.dhtValues = map[string][]byte{}
	}
	f.dhtValues[key] = append([]byte(nil), value...)
	return nil
}
func (f *fakeDiscoveryNode) GetValue(_ context.Context, key string) ([]byte, error) {
	v, ok := f.dhtValues[key]
	if !ok {
		return nil, context.Canceled
	}
	return append([]byte(nil), v...), nil
}
func (f *fakeDiscoveryNode) Discover(context.Context, string) (<-chan peer.AddrInfo, error) {
	return f.discoverCh, nil
}
func (f *fakeDiscoveryNode) Connect(ctx context.Context, pi peer.AddrInfo) error {
	return f.host.Connect(ctx, pi)
}

var _ samnet.Node = (*fakeDiscoveryNode)(nil)

func TestDiscoverReturnsVerifiedCards(t *testing.T) {
	ctx := context.Background()

	providerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New provider error = %v", err)
	}
	defer providerHost.Close()

	consumerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New consumer error = %v", err)
	}
	defer consumerHost.Close()

	providerPriv := providerHost.Peerstore().PrivKey(providerHost.ID())
	card, err := protocol.NewAgentCard(providerHost.ID(), []string{"inference"}, nil, providerPriv)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}

	providerHost.SetStreamHandler(protocol.AgentCardProtocolID, func(s network.Stream) {
		defer s.Close()
		_ = json.NewEncoder(s).Encode(card)
	})

	ch := make(chan peer.AddrInfo, 1)
	ch <- peer.AddrInfo{ID: providerHost.ID(), Addrs: providerHost.Addrs()}
	close(ch)

	node := &fakeDiscoveryNode{host: consumerHost, peerID: consumerHost.ID(), discoverCh: ch}
	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		t.Fatalf("NewDiscoveryService() error = %v", err)
	}

	cards, err := svc.Discover(ctx, "inference")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(cards) != 1 {
		t.Fatalf("len(cards) = %d, want 1", len(cards))
	}
	if cards[0].PeerID != providerHost.ID().String() {
		t.Fatalf("card peer ID = %q, want %q", cards[0].PeerID, providerHost.ID())
	}
}

func TestDiscoverPeerIDsReturnsUniqueRemotePeers(t *testing.T) {
	ctx := context.Background()

	consumerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New consumer error = %v", err)
	}
	defer consumerHost.Close()

	providerA, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New providerA error = %v", err)
	}
	defer providerA.Close()

	providerB, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New providerB error = %v", err)
	}
	defer providerB.Close()

	ch := make(chan peer.AddrInfo, 5)
	ch <- peer.AddrInfo{ID: providerA.ID(), Addrs: providerA.Addrs()}
	ch <- peer.AddrInfo{ID: providerA.ID(), Addrs: providerA.Addrs()}
	ch <- peer.AddrInfo{ID: consumerHost.ID(), Addrs: consumerHost.Addrs()}
	ch <- peer.AddrInfo{ID: providerB.ID(), Addrs: providerB.Addrs()}
	close(ch)

	node := &fakeDiscoveryNode{host: consumerHost, peerID: consumerHost.ID(), discoverCh: ch}
	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		t.Fatalf("NewDiscoveryService() error = %v", err)
	}

	ids, err := svc.DiscoverPeerIDs(ctx, "inference")
	if err != nil {
		t.Fatalf("DiscoverPeerIDs() error = %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("len(ids) = %d, want 2", len(ids))
	}
	seen := map[peer.ID]struct{}{}
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	if _, ok := seen[providerA.ID()]; !ok {
		t.Fatalf("providerA peer ID missing from discovered IDs")
	}
	if _, ok := seen[providerB.ID()]; !ok {
		t.Fatalf("providerB peer ID missing from discovered IDs")
	}
}

func TestDiscoverAndConnectReturnsPartialSuccess(t *testing.T) {
	ctx := context.Background()

	consumerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New consumer error = %v", err)
	}
	defer consumerHost.Close()

	provider, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New provider error = %v", err)
	}
	defer provider.Close()

	priv, _, err := crypto.GenerateEd25519Key(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	unreachableID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	ch := make(chan peer.AddrInfo, 2)
	ch <- peer.AddrInfo{ID: provider.ID(), Addrs: provider.Addrs()}
	ch <- peer.AddrInfo{ID: unreachableID}
	close(ch)

	node := &fakeDiscoveryNode{host: consumerHost, peerID: consumerHost.ID(), discoverCh: ch}
	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		t.Fatalf("NewDiscoveryService() error = %v", err)
	}

	connected, err := svc.DiscoverAndConnect(ctx, "inference")
	if len(connected) != 1 || connected[0] != provider.ID() {
		t.Fatalf("connected = %#v, want [%s]", connected, provider.ID())
	}
	if err == nil {
		t.Fatal("DiscoverAndConnect() expected partial connect error, got nil")
	}
	if got := err.Error(); got == "" {
		t.Fatal("DiscoverAndConnect() error should include failed connect detail")
	}
}

func TestDiscoverPrefersDHTCard(t *testing.T) {
	ctx := context.Background()

	consumerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New consumer error = %v", err)
	}
	defer consumerHost.Close()

	priv, _, err := crypto.GenerateEd25519Key(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	providerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	card, err := protocol.NewAgentCard(providerID, []string{"inference"}, nil, priv)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}
	raw, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("json.Marshal(card) error = %v", err)
	}

	ch := make(chan peer.AddrInfo, 1)
	ch <- peer.AddrInfo{ID: providerID}
	close(ch)

	node := &fakeDiscoveryNode{
		host:       consumerHost,
		peerID:     consumerHost.ID(),
		discoverCh: ch,
		dhtValues: map[string][]byte{
			protocol.DHTPeerCardKey(providerID.String()): raw,
		},
	}

	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		t.Fatalf("NewDiscoveryService() error = %v", err)
	}

	cards, err := svc.Discover(ctx, "inference")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(cards) != 1 {
		t.Fatalf("len(cards) = %d, want 1", len(cards))
	}
	if cards[0].PeerID != providerID.String() {
		t.Fatalf("card peer ID = %q, want %q", cards[0].PeerID, providerID)
	}
}

func TestDiscoverFallsBackToStreamWhenDHTCardInvalid(t *testing.T) {
	ctx := context.Background()

	providerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New provider error = %v", err)
	}
	defer providerHost.Close()

	consumerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New consumer error = %v", err)
	}
	defer consumerHost.Close()

	providerPriv := providerHost.Peerstore().PrivKey(providerHost.ID())
	card, err := protocol.NewAgentCard(providerHost.ID(), []string{"inference"}, nil, providerPriv)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}

	providerHost.SetStreamHandler(protocol.AgentCardProtocolID, func(s network.Stream) {
		defer s.Close()
		_ = json.NewEncoder(s).Encode(card)
	})

	ch := make(chan peer.AddrInfo, 1)
	ch <- peer.AddrInfo{ID: providerHost.ID(), Addrs: providerHost.Addrs()}
	close(ch)

	node := &fakeDiscoveryNode{
		host:       consumerHost,
		peerID:     consumerHost.ID(),
		discoverCh: ch,
		dhtValues: map[string][]byte{
			protocol.DHTPeerCardKey(providerHost.ID().String()): []byte("not-json"),
		},
	}

	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		t.Fatalf("NewDiscoveryService() error = %v", err)
	}

	cards, err := svc.Discover(ctx, "inference")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(cards) != 1 {
		t.Fatalf("len(cards) = %d, want 1", len(cards))
	}
	if cards[0].PeerID != providerHost.ID().String() {
		t.Fatalf("card peer ID = %q, want %q", cards[0].PeerID, providerHost.ID())
	}
}

func TestDiscoverAllowsStaleDHTCardWhenMaxAgeDisabled(t *testing.T) {
	ctx := context.Background()

	consumerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New consumer error = %v", err)
	}
	defer consumerHost.Close()

	priv, _, err := crypto.GenerateEd25519Key(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	providerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	card, err := protocol.NewAgentCard(providerID, []string{"inference"}, nil, priv)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}
	card.IssuedAt = time.Now().Add(-2 * time.Hour).UTC()
	if err := card.Sign(priv); err != nil {
		t.Fatalf("card.Sign() error = %v", err)
	}

	raw, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("json.Marshal(card) error = %v", err)
	}

	ch := make(chan peer.AddrInfo, 1)
	ch <- peer.AddrInfo{ID: providerID}
	close(ch)

	node := &fakeDiscoveryNode{
		host:       consumerHost,
		peerID:     consumerHost.ID(),
		discoverCh: ch,
		dhtValues: map[string][]byte{
			protocol.DHTPeerCardKey(providerID.String()): raw,
		},
	}

	svc, err := protocol.NewDiscoveryService(node, protocol.WithMaxDHTCardAge(0))
	if err != nil {
		t.Fatalf("NewDiscoveryService() error = %v", err)
	}

	cards, err := svc.Discover(ctx, "inference")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(cards) != 1 {
		t.Fatalf("len(cards) = %d, want 1", len(cards))
	}
	if cards[0].PeerID != providerID.String() {
		t.Fatalf("card peer ID = %q, want %q", cards[0].PeerID, providerID)
	}
}
