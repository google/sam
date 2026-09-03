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

package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

var logger = golog.Logger("sam-node")

// GetOrGenerateKey retrieves a persistent private key or creates one if it's the first run
func GetOrGenerateKey(s *Store) crypto.PrivKey {
	kb, _ := s.LoadKey()
	if len(kb) == 0 {
		logger.Info("[Store] Generating new Peer Identity...")
		priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			logger.Fatalf("Failed to generate key: %v", err)
		}
		raw, err := crypto.MarshalPrivateKey(priv)
		if err != nil {
			logger.Fatalf("Failed to marshal private key: %v", err)
		}
		if err := s.SaveKey(raw); err != nil {
			logger.Fatalf("Failed to save key: %v", err)
		}
		return priv
	}
	priv, err := crypto.UnmarshalPrivateKey(kb)
	if err != nil {
		logger.Fatalf("Corrupt key in store: %v", err)
	}
	return priv
}

func (n *SamNode) Enroll(ctx context.Context, controlPlaneURL string, jwt string) error {
	pubKey := n.Host.Peerstore().PubKey(n.Host.ID())
	enrollResp, err := n.enrollHTTP(ctx, controlPlaneURL, jwt, n.Host.ID(), pubKey)
	if err != nil {
		return err
	}

	return n.connectToRouters(ctx, enrollResp.RouterAddresses)
}

// enrollHTTP performs the HTTP half of enrollment for an explicit peer
// identity, so it can run before the libp2p host exists (startup recovery).
func (n *SamNode) enrollHTTP(ctx context.Context, controlPlaneURL, jwt string, peerID peer.ID, pubKey crypto.PubKey) (*api.EnrollResponse, error) {
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	req := &api.EnrollRequest{
		Jwt:           jwt,
		PeerId:        peerID.String(),
		PublicKey:     pubBytes,
		RequestedRole: n.config.RequiredRole,
		Labels:        n.config.Labels, // validated at startup
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enroll request: %v", err)
	}

	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		return nil, fmt.Errorf("control plane address must be an HTTP or HTTPS URL for enrollment: %s", controlPlaneURL)
	}
	url := controlPlaneURL + "/register"
	logger.Infof("Enrolling via HTTP at %s", url)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("failed to close response body: %v", err)
		}
	}()

	return n.processEnrollResponse(resp)
}

// recoverStaleIdentity re-enrolls over HTTP with a JWT obtained from the
// stored refresh token, keeping the node's PeerID. It must not touch n.Host:
// it runs before the host exists, and router connection happens in the
// normal startup path afterwards.
func (n *SamNode) recoverStaleIdentity(ctx context.Context) error {
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil || controlPlaneURL == "" {
		return fmt.Errorf("no control plane URL in store")
	}
	jwt, err := n.renewWithRefreshToken(ctx, "")
	if err != nil {
		return err
	}
	privKey := GetOrGenerateKey(n.Store)
	peerID, err := peer.IDFromPublicKey(privKey.GetPublic())
	if err != nil {
		return fmt.Errorf("failed to derive peer ID from stored key: %w", err)
	}
	_, err = n.enrollHTTP(ctx, controlPlaneURL, jwt, peerID, privKey.GetPublic())
	return err
}

func (n *SamNode) processEnrollResponse(resp *http.Response) (*api.EnrollResponse, error) {
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enrollment failed with status %s: %s", resp.Status, string(body))
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(respData, &enrollResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if enrollResp.ErrorMessage != "" {
		return nil, fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}
	if len(enrollResp.BiscuitToken) == 0 {
		return nil, fmt.Errorf("received empty biscuit token")
	}
	if len(enrollResp.ControlPlanePublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("received invalid control plane public key size: %d bytes (expected %d)", len(enrollResp.ControlPlanePublicKey), ed25519.PublicKeySize)
	}

	if n.config.RequiredRole != "" {
		if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, ed25519.PublicKey(enrollResp.ControlPlanePublicKey), n.config.RequiredRole, n.BiscuitTimeout); err != nil {
			return nil, fmt.Errorf("enrolled biscuit token lacks required role %q: %w", n.config.RequiredRole, err)
		}
	}

	if err := n.Store.SaveIdentity(enrollResp.BiscuitToken); err != nil {
		return nil, fmt.Errorf("failed to save identity: %v", err)
	}
	n.SetIdentityCache(enrollResp.BiscuitToken)

	if err := n.Store.SaveIdentityExpiration(enrollResp.Expiration); err != nil {
		return nil, fmt.Errorf("failed to save identity expiration: %v", err)
	}
	if err := n.Store.SaveMeshConfig(enrollResp.ControlPlanePublicKey, enrollResp.RouterAddresses); err != nil {
		return nil, fmt.Errorf("failed to save mesh config: %v", err)
	}

	n.addTrustedKey(ed25519.PublicKey(enrollResp.ControlPlanePublicKey))

	return &enrollResp, nil
}

func (n *SamNode) connectToRouters(ctx context.Context, addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("failed to connect and authenticate after HTTP enrollment: control plane returned no router addresses")
	}

	var lastAuthErr error
	for _, addrStr := range addrs {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("Failed to parse router address from response: %v", err)
			continue
		}
		if err := n.ConnectAndAuthWithRouter(ctx, addr); err != nil {
			logger.Warnf("Failed to connect and auth with router after enrollment: %v", err)
			lastAuthErr = err
		} else {
			logger.Info("Successfully enrolled via HTTP and stored identity and mesh config.")
			return nil
		}
	}

	return fmt.Errorf("failed to connect and authenticate with any router after HTTP enrollment (last error: %v)", lastAuthErr)
}

// EnrollBootstrap enrolls the node with the control plane using a pre-shared bootstrap token.
// If the enrollment status is PENDING, it polls the status endpoint until approved or rejected.
func (n *SamNode) EnrollBootstrap(ctx context.Context, controlPlaneURL string, bootstrapToken string) error {
	pubKey := n.Host.Peerstore().PubKey(n.Host.ID())
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	enrollTS := time.Now().UnixMilli()
	enrollSig, err := n.config.PrivKey.Sign(api.EnrollChallenge(n.Host.ID().String(), enrollTS))
	if err != nil {
		return fmt.Errorf("failed to sign enrollment challenge: %w", err)
	}

	req := &api.BootstrapEnrollRequest{
		BootstrapToken:     bootstrapToken,
		PeerId:             n.Host.ID().String(),
		PublicKey:          pubBytes,
		RequestedRole:      n.config.RequiredRole,
		Labels:             n.config.Labels, // validated at startup
		Timestamp:          enrollTS,
		ChallengeSignature: enrollSig,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal bootstrap enroll request: %w", err)
	}

	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		return fmt.Errorf("control plane address must be an HTTP or HTTPS URL for enrollment: %s", controlPlaneURL)
	}
	enrollURL := controlPlaneURL + "/enroll"
	logger.Infof("Enrolling via Bootstrap token at %s", enrollURL)

	client := &http.Client{Timeout: 30 * time.Second}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", enrollURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment failed with status %s: %s", resp.Status, string(body))
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	enrollResp := &api.BootstrapEnrollResponse{}
	if err := proto.Unmarshal(respData, enrollResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if enrollResp.ErrorMessage != "" {
		return fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}

	if enrollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		logger.Infof("Enrollment is pending approval. Polling status...")

		u, err := url.Parse(controlPlaneURL)
		if err != nil {
			return fmt.Errorf("invalid control plane URL: %w", err)
		}
		u = u.JoinPath("enroll", "status")
		q := u.Query()
		q.Set("peer_id", n.Host.ID().String())
		u.RawQuery = q.Encode()
		statusURL := u.String()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

	pollLoop:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				// Prove possession of the enrollment key on every poll; the
				// control plane returns the biscuit only to the enrollee.
				ts := time.Now().UnixMilli()
				sig, err := n.config.PrivKey.Sign(api.EnrollStatusChallenge(n.Host.ID().String(), ts))
				if err != nil {
					return fmt.Errorf("failed to sign enrollment status challenge: %w", err)
				}
				hReq, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
				if err != nil {
					return fmt.Errorf("failed to create status request: %w", err)
				}
				hReq.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(ts, 10))
				hReq.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(sig))

				hResp, err := client.Do(hReq)
				if err != nil {
					logger.Warnf("Failed to check enrollment status: %v", err)
					continue
				}

				if hResp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(hResp.Body)
					_ = hResp.Body.Close()
					logger.Warnf("Status check returned status %s: %s", hResp.Status, string(body))
					continue
				}

				hRespData, err := io.ReadAll(hResp.Body)
				_ = hResp.Body.Close()
				if err != nil {
					logger.Warnf("Failed to read status response body: %v", err)
					continue
				}

				statusResp := &api.BootstrapEnrollResponse{}
				if err := proto.Unmarshal(hRespData, statusResp); err != nil {
					logger.Warnf("Failed to unmarshal status response: %v", err)
					continue
				}

				if statusResp.ErrorMessage != "" {
					return fmt.Errorf("enrollment failed: %s", statusResp.ErrorMessage)
				}

				if statusResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
					enrollResp = statusResp
					break pollLoop
				} else if statusResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
					return fmt.Errorf("enrollment was rejected by administrator")
				}
			}
		}
	}

	if len(enrollResp.BiscuitToken) == 0 {
		return fmt.Errorf("received empty biscuit token from enrollment response")
	}

	if len(enrollResp.ControlPlanePublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("received invalid control plane public key size: %d bytes", len(enrollResp.ControlPlanePublicKey))
	}

	if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, ed25519.PublicKey(enrollResp.ControlPlanePublicKey), n.config.RequiredRole, n.BiscuitTimeout); err != nil {
		return fmt.Errorf("enrolled biscuit token lacks required role %q: %w", n.config.RequiredRole, err)
	}

	if err := n.Store.SaveIdentity(enrollResp.BiscuitToken); err != nil {
		return fmt.Errorf("failed to save identity: %v", err)
	}
	n.SetIdentityCache(enrollResp.BiscuitToken)

	if err := n.Store.SaveIdentityExpiration(enrollResp.Expiration); err != nil {
		return fmt.Errorf("failed to save identity expiration: %v", err)
	}

	if err := n.Store.SaveMeshConfig(enrollResp.ControlPlanePublicKey, enrollResp.RouterAddresses); err != nil {
		return fmt.Errorf("failed to save mesh config: %v", err)
	}

	n.addTrustedKey(ed25519.PublicKey(enrollResp.ControlPlanePublicKey))

	// Connect and Auth to router after enrollment to join the mesh
	if len(enrollResp.RouterAddresses) == 0 {
		return fmt.Errorf("failed to connect and authenticate after bootstrap enrollment: control plane returned no router addresses")
	}

	var lastAuthErr error
	var authed bool
	for _, addrStr := range enrollResp.RouterAddresses {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("Failed to parse router address: %v", err)
			continue
		}
		if err := n.ConnectAndAuthWithRouter(ctx, addr); err != nil {
			logger.Warnf("Failed to connect and auth with router: %v", err)
			lastAuthErr = err
		} else {
			authed = true
			break
		}
	}

	if !authed {
		return fmt.Errorf("failed to connect/auth with router after bootstrap enrollment (last error: %v)", lastAuthErr)
	}

	logger.Info("Successfully enrolled via Bootstrap token and joined mesh.")
	return nil
}
