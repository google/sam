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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/sam/api"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
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
		raw, _ := crypto.MarshalPrivateKey(priv)
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

func (n *SamNode) Enroll(ctx context.Context, hubURL string, jwt string) error {
	req := &api.EnrollRequest{
		Jwt:    jwt,
		PeerId: n.Host.ID().String(),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal enroll request: %v", err)
	}

	if !strings.HasPrefix(hubURL, "http://") && !strings.HasPrefix(hubURL, "https://") {
		return fmt.Errorf("hub address must be an HTTP or HTTPS URL for enrollment: %s", hubURL)
	}
	url := hubURL + "/register"
	logger.Infof("Enrolling via HTTP at %s", url)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment failed with status %s: %s", resp.Status, string(body))
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(respData, &enrollResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if enrollResp.ErrorMessage != "" {
		return fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}

	if len(enrollResp.BiscuitToken) == 0 {
		return fmt.Errorf("received empty biscuit token")
	}

	if len(enrollResp.HubPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("received invalid hub public key size: %d bytes (expected %d)", len(enrollResp.HubPublicKey), ed25519.PublicKeySize)
	}

	if err := n.Store.SaveIdentity(enrollResp.BiscuitToken); err != nil {
		return fmt.Errorf("failed to save identity: %v", err)
	}
	n.SetIdentityCache(enrollResp.BiscuitToken)

	if err := n.Store.SaveIdentityExpiration(enrollResp.Expiration); err != nil {
		return fmt.Errorf("failed to save identity expiration: %v", err)
	}

	if err := n.Store.SaveHubConfig(enrollResp.HubPublicKey, enrollResp.HubAddresses); err != nil {
		return fmt.Errorf("failed to save hub config: %v", err)
	}

	n.keysMu.Lock()
	n.trustedKeys = append(n.trustedKeys, TrustedKey{Key: ed25519.PublicKey(enrollResp.HubPublicKey), ReceivedAt: time.Now()})
	n.keysMu.Unlock()

	// Connect and Auth to hub after enrollment to join the mesh
	var lastAuthErr error
	var authed bool
	for _, addrStr := range enrollResp.HubAddresses {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("Failed to parse hub address from response: %v", err)
			continue
		}
		if err := n.ConnectAndAuthWithHub(ctx, addr); err != nil {
			logger.Warnf("Failed to connect and auth with hub after enrollment: %v", err)
			lastAuthErr = err
		} else {
			authed = true
			break
		}
	}

	if !authed {
		return fmt.Errorf("failed to connect and authenticate with any hub after HTTP enrollment (last error: %v)", lastAuthErr)
	}

	logger.Info("Successfully enrolled via HTTP and stored identity and hub config.")
	return nil
}

// EnrollBootstrap enrolls the node with the control plane using a pre-shared bootstrap token.
// If the enrollment status is PENDING, it polls the status endpoint until approved or rejected.
func (n *SamNode) EnrollBootstrap(ctx context.Context, hubURL string, bootstrapToken string) error {
	pubKey := n.Host.Peerstore().PubKey(n.Host.ID())
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	req := &api.BootstrapEnrollRequest{
		BootstrapToken: bootstrapToken,
		PeerId:         n.Host.ID().String(),
		PublicKey:      pubBytes,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal bootstrap enroll request: %w", err)
	}

	if !strings.HasPrefix(hubURL, "http://") && !strings.HasPrefix(hubURL, "https://") {
		return fmt.Errorf("hub address must be an HTTP or HTTPS URL for enrollment: %s", hubURL)
	}
	url := hubURL + "/enroll"
	logger.Infof("Enrolling via Bootstrap token at %s", url)

	client := &http.Client{Timeout: 30 * time.Second}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
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
		statusReq := &api.EnrollmentStatusRequest{
			PeerId: n.Host.ID().String(),
		}
		statusData, err := proto.Marshal(statusReq)
		if err != nil {
			return fmt.Errorf("failed to marshal status request: %w", err)
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

	pollLoop:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				statusURL := hubURL + "/enroll/status"
				hReq, err := http.NewRequestWithContext(ctx, "POST", statusURL, bytes.NewReader(statusData))
				if err != nil {
					return fmt.Errorf("failed to create status request: %w", err)
				}
				hReq.Header.Set("Content-Type", "application/x-protobuf")

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

	if len(enrollResp.HubPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("received invalid hub public key size: %d bytes", len(enrollResp.HubPublicKey))
	}

	if err := n.Store.SaveIdentity(enrollResp.BiscuitToken); err != nil {
		return fmt.Errorf("failed to save identity: %v", err)
	}
	n.SetIdentityCache(enrollResp.BiscuitToken)

	if err := n.Store.SaveIdentityExpiration(enrollResp.Expiration); err != nil {
		return fmt.Errorf("failed to save identity expiration: %v", err)
	}

	if err := n.Store.SaveHubConfig(enrollResp.HubPublicKey, enrollResp.HubAddresses); err != nil {
		return fmt.Errorf("failed to save hub config: %v", err)
	}

	n.keysMu.Lock()
	n.trustedKeys = append(n.trustedKeys, TrustedKey{Key: ed25519.PublicKey(enrollResp.HubPublicKey), ReceivedAt: time.Now()})
	n.keysMu.Unlock()

	// Connect and Auth to hub after enrollment to join the mesh
	var lastAuthErr error
	var authed bool
	for _, addrStr := range enrollResp.HubAddresses {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("Failed to parse hub address: %v", err)
			continue
		}
		if err := n.ConnectAndAuthWithHub(ctx, addr); err != nil {
			logger.Warnf("Failed to connect and auth with hub: %v", err)
			lastAuthErr = err
		} else {
			authed = true
			break
		}
	}

	if !authed {
		return fmt.Errorf("failed to connect/auth with hub after bootstrap enrollment (last error: %v)", lastAuthErr)
	}

	logger.Info("Successfully enrolled via Bootstrap token and joined mesh.")
	return nil
}
