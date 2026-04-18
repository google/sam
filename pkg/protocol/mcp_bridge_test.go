package protocol

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"sam/pkg/economy"
)

type fakeVerifier struct {
	mu       sync.Mutex
	decision *economy.VerifyDecision
	err      error
	lastReq  economy.VerifyRequest
}

func (f *fakeVerifier) Verify(_ context.Context, req economy.VerifyRequest) (*economy.VerifyDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	if f.decision == nil {
		f.decision = &economy.VerifyDecision{Subject: "peer:test"}
	}
	return f.decision, nil
}

func (f *fakeVerifier) GetLastReq() economy.VerifyRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

type echoConnector struct{}

func (echoConnector) Open(context.Context) (mcp.Transport, error) {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := b.Read(buf)
			if n > 0 {
				if _, werr := b.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return &mcp.IOTransport{Reader: a, Writer: a}, nil
}

func TestMCPBridgeAllowsAuthorizedStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(server) error = %v", err)
	}
	defer serverHost.Close()

	clientHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(client) error = %v", err)
	}
	defer clientHost.Close()

	verifier := &fakeVerifier{}
	_, err = NewMCPBridge(serverHost, verifier, echoConnector{})
	if err != nil {
		t.Fatalf("NewMCPBridge() error = %v", err)
	}

	if err := clientHost.Connect(ctx, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatalf("client connect error = %v", err)
	}

	clientBridge, err := NewMCPBridge(clientHost, verifier, echoConnector{})
	if err != nil {
		t.Fatalf("NewMCPBridge(client) error = %v", err)
	}

	stream, err := clientBridge.Open(ctx, serverHost.ID(), BridgeOpenRequest{
		BiscuitToken: "token-1",
		Amount:       10,
		Asset:        "sam-credit",
		Nonce:        "n-1",
		Capability:   "agent.chat",
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer stream.Close()

	payload := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo = %q, want %q", string(buf), string(payload))
	}

	if verifier.GetLastReq().Token != "token-1" || verifier.GetLastReq().Payment.Amount != 10 {
		t.Fatalf("verifier request = %#v, want token and amount", verifier.GetLastReq())
	}
}

func TestMCPBridgeDeniesUnauthorizedStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(server) error = %v", err)
	}
	defer serverHost.Close()

	clientHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(client) error = %v", err)
	}
	defer clientHost.Close()

	denyVerifier := &fakeVerifier{err: errors.New("insufficient funds")}
	_, err = NewMCPBridge(serverHost, denyVerifier, echoConnector{})
	if err != nil {
		t.Fatalf("NewMCPBridge(server) error = %v", err)
	}

	if err := clientHost.Connect(ctx, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatalf("client connect error = %v", err)
	}

	clientBridge, err := NewMCPBridge(clientHost, &fakeVerifier{}, echoConnector{})
	if err != nil {
		t.Fatalf("NewMCPBridge(client) error = %v", err)
	}

	stream, err := clientBridge.Open(ctx, serverHost.ID(), BridgeOpenRequest{
		BiscuitToken: "token-deny",
		Amount:       1,
		Asset:        "sam-credit",
		Nonce:        "n-deny",
		Capability:   "agent.chat",
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer stream.Close()

	buf := make([]byte, 2048)
	n, err := stream.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("stream.Read() error = %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, economy.ErrVerifierDeniedRequest.Error()) {
		t.Fatalf("response = %q, want verifier denied error", resp)
	}
}
