package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	coreprotocol "github.com/libp2p/go-libp2p/core/protocol"
)

const PassportAuthProtocolID coreprotocol.ID = "/sam/auth/passport/1.0"

type passportAuthRequest struct {
	Passport string `json:"passport"`
}

type passportAuthResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type passportAuthManager struct {
	host         host.Host
	federationID string

	mu            sync.RWMutex
	localPassport string
	peerClaims    map[string]*PassportClaims
	installed     bool
}

var passportAuthManagers sync.Map

func EnsurePassportAuth(h host.Host, federationID string) error {
	if h == nil {
		return fmt.Errorf("host is nil")
	}
	mgr := getOrCreatePassportAuthManager(h)
	mgr.mu.Lock()
	if federationID != "" {
		mgr.federationID = federationID
	}
	if mgr.installed {
		mgr.mu.Unlock()
		return nil
	}
	mgr.installed = true
	mgr.mu.Unlock()

	h.SetStreamHandler(PassportAuthProtocolID, mgr.handleStream)
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, conn network.Conn) {
			go func() {
				_ = AuthenticatePeerPassport(context.Background(), h, conn.RemotePeer())
			}()
		},
		DisconnectedF: func(_ network.Network, conn network.Conn) {
			mgr.mu.Lock()
			delete(mgr.peerClaims, conn.RemotePeer().String())
			mgr.mu.Unlock()
		},
	})
	return nil
}

func SetLocalPassport(h host.Host, federationID string, passport string) error {
	if err := EnsurePassportAuth(h, federationID); err != nil {
		return err
	}
	mgr := getOrCreatePassportAuthManager(h)
	mgr.mu.Lock()
	mgr.localPassport = passport
	mgr.mu.Unlock()
	return nil
}

func AuthenticatePeerPassport(ctx context.Context, h host.Host, target peer.ID) error {
	if h == nil {
		return fmt.Errorf("host is nil")
	}
	if target == "" {
		return fmt.Errorf("target peer id is required")
	}
	mgr := getOrCreatePassportAuthManager(h)
	if _, ok := mgr.claimsFor(target); ok {
		return nil
	}
	mgr.mu.RLock()
	localPassport := mgr.localPassport
	mgr.mu.RUnlock()
	if localPassport == "" {
		return fmt.Errorf("local passport is not configured")
	}

	stream, err := h.NewStream(ctx, target, PassportAuthProtocolID)
	if err != nil {
		return fmt.Errorf("opening passport auth stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	if err := json.NewEncoder(stream).Encode(passportAuthRequest{Passport: localPassport}); err != nil {
		return fmt.Errorf("writing passport auth request: %w", err)
	}
	var resp passportAuthResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return fmt.Errorf("reading passport auth response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "passport authentication rejected"
		}
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func AuthenticatedPeerPassport(h host.Host, target peer.ID) (*PassportClaims, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	if target == "" {
		return nil, fmt.Errorf("target peer id is required")
	}
	mgr := getOrCreatePassportAuthManager(h)
	claims, ok := mgr.claimsFor(target)
	if !ok {
		return nil, fmt.Errorf("peer %s has not completed passport authentication", target)
	}
	return claims, nil
}

func getOrCreatePassportAuthManager(h host.Host) *passportAuthManager {
	if mgr, ok := passportAuthManagers.Load(h); ok {
		return mgr.(*passportAuthManager)
	}
	mgr := &passportAuthManager{host: h, federationID: "default", peerClaims: map[string]*PassportClaims{}}
	actual, _ := passportAuthManagers.LoadOrStore(h, mgr)
	return actual.(*passportAuthManager)
}

func (m *passportAuthManager) claimsFor(target peer.ID) (*PassportClaims, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	claims, ok := m.peerClaims[target.String()]
	return claims, ok
}

func (m *passportAuthManager) handleStream(stream network.Stream) {
	defer func() { _ = stream.Close() }()

	var req passportAuthRequest
	if err := json.NewDecoder(stream).Decode(&req); err != nil {
		_ = json.NewEncoder(stream).Encode(passportAuthResponse{Error: fmt.Sprintf("invalid passport auth request: %v", err)})
		return
	}
	claims, err := ValidatePassportBiscuit(context.Background(), req.Passport, stream.Conn().RemotePeer().String(), m.federationID)
	if err != nil {
		_ = json.NewEncoder(stream).Encode(passportAuthResponse{Error: fmt.Sprintf("invalid passport: %v", err)})
		return
	}
	m.mu.Lock()
	m.peerClaims[stream.Conn().RemotePeer().String()] = claims
	m.mu.Unlock()
	_ = json.NewEncoder(stream).Encode(passportAuthResponse{OK: true})
}
