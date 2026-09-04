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
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// FetchControlPlaneInfo retrieves the latest configuration from the control plane's /info endpoint.
func FetchControlPlaneInfo(ctx context.Context, controlPlaneURL string) (*api.ControlPlaneInfoResponse, error) {
	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		controlPlaneURL = "https://" + controlPlaneURL
	}
	controlPlaneURL = strings.TrimSuffix(controlPlaneURL, "/")

	urlStr := controlPlaneURL + "/info"
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned status %s: %s", resp.Status, string(body))
	}

	var info api.ControlPlaneInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to decode /info response: %w", err)
	}

	return &info, nil
}

// FetchControlPlaneKeys retrieves the full set of currently valid control
// plane public keys from the /keys endpoint — the same catch-up path routers
// use. Enrollment only hands out the newest key, so this is how a node
// learns keys still in their rotation grace period, or rotations it missed
// while offline.
func FetchControlPlaneKeys(ctx context.Context, controlPlaneURL string) ([]ed25519.PublicKey, error) {
	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		controlPlaneURL = "https://" + controlPlaneURL
	}
	controlPlaneURL = strings.TrimSuffix(controlPlaneURL, "/")

	req, err := http.NewRequestWithContext(ctx, "GET", controlPlaneURL+"/keys", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned status %s: %s", resp.Status, string(body))
	}

	var keysResp api.KeysResponse
	if err := proto.Unmarshal(body, &keysResp); err != nil {
		return nil, fmt.Errorf("failed to decode /keys response: %w", err)
	}

	var keys []ed25519.PublicKey
	for _, kb := range keysResp.PublicKeys {
		if len(kb) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(kb))
		}
	}
	return keys, nil
}

// mergeTrustedKeys replaces the stored trust set with the authoritative set
// from /keys, preserving ReceivedAt for keys already known so local grace
// pruning keeps working across syncs.
func mergeTrustedKeys(existing []TrustedKey, fetched []ed25519.PublicKey, now time.Time) []TrustedKey {
	merged := make([]TrustedKey, 0, len(fetched))
	for _, key := range fetched {
		tk := TrustedKey{Key: key, ReceivedAt: now}
		for _, old := range existing {
			if bytes.Equal(old.Key, key) {
				tk.ReceivedAt = old.ReceivedAt
				break
			}
		}
		merged = append(merged, tk)
	}
	return merged
}

// SyncMeshConfig loads the mesh configuration from the store, attempts to refresh it
// via HTTP from the control plane, and updates the store if successful.
// It returns the control plane public key, the latest multiaddresses, and the
// control plane's current ban set.
//
// The ban set is deliberately not persisted. MeshEvent_BANNED is published once
// and gossip has no replay, so a node that restarted or was offline has to be
// told again; /info is that catch-up, and reading it fresh each start is also
// what makes an unban take effect. Nil means the control plane was not reached,
// which is not the same as "nothing is banned": callers must not treat it as an
// instruction to clear anything.
func SyncMeshConfig(ctx context.Context, s *Store) ([]byte, []multiaddr.Multiaddr, []string, error) {
	pubKey, storedAddrsStr, err := s.LoadMeshConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load mesh config from store: %w", err)
	}

	controlPlaneURL, err := s.LoadControlPlaneURL()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load control plane URL from store: %w", err)
	}
	var bannedPeerIDs []string
	var routerAddrs []multiaddr.Multiaddr

	// Parse stored addresses
	for _, addrStr := range storedAddrsStr {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("Failed to parse stored router address %q: %v", addrStr, err)
			continue
		}
		routerAddrs = append(routerAddrs, ma)
	}

	// If we have a URL, fetch the latest info
	if controlPlaneURL != "" {
		logger.Infof("Fetching latest router addresses via HTTP from %s...", controlPlaneURL)
		info, err := FetchControlPlaneInfo(ctx, controlPlaneURL)
		if err != nil {
			logger.Warnf("Failed to fetch updated addresses via HTTP (using cached): %v", err)
		} else if bannedPeerIDs = info.GetBannedPeerIds(); len(info.RouterAddresses) > 0 {
			logger.Infof("Discovered latest router addresses: %v", info.RouterAddresses)
			var newRouterAddrs []multiaddr.Multiaddr
			for _, addrStr := range info.RouterAddresses {
				ma, parseErr := multiaddr.NewMultiaddr(addrStr)
				if parseErr != nil {
					logger.Warnf("Failed to parse discovered router address %q: %v", addrStr, parseErr)
					continue
				}
				newRouterAddrs = append(newRouterAddrs, ma)
			}
			if len(newRouterAddrs) > 0 {
				routerAddrs = newRouterAddrs
				if len(pubKey) > 0 {
					if saveErr := s.SaveMeshConfig(pubKey, info.RouterAddresses); saveErr != nil {
						logger.Errorf("Failed to save updated mesh config to store: %v", saveErr)
					}
				}
			}
		}

		// Catch up on the valid key set: an empty result would wipe the trust
		// set, so it is ignored like any fetch failure.
		if keys, keysErr := FetchControlPlaneKeys(ctx, controlPlaneURL); keysErr != nil {
			logger.Warnf("Failed to fetch control plane keys via HTTP (using cached): %v", keysErr)
		} else if len(keys) > 0 {
			existing, loadErr := s.LoadTrustedKeys()
			if loadErr != nil {
				logger.Warnf("Failed to load stored trusted keys, replacing: %v", loadErr)
			}
			if saveErr := s.SaveTrustedKeys(mergeTrustedKeys(existing, keys, time.Now())); saveErr != nil {
				logger.Errorf("Failed to save trusted keys to store: %v", saveErr)
			}
		}
	}

	return pubKey, routerAddrs, bannedPeerIDs, nil
}

// FetchMeshPolicy retrieves the latest mesh policy from the control plane's /policies endpoint using a biscuit token.
func FetchMeshPolicy(ctx context.Context, controlPlaneURL string, biscuitToken []byte) (*api.PolicyConfigGetResponse, error) {
	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		controlPlaneURL = "https://" + controlPlaneURL
	}
	controlPlaneURL = strings.TrimSuffix(controlPlaneURL, "/")

	urlStr := controlPlaneURL + "/policies"
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuitToken))

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned status %s: %s", resp.Status, string(body))
	}

	var policyResp api.PolicyConfigGetResponse
	if err := proto.Unmarshal(body, &policyResp); err != nil {
		return nil, fmt.Errorf("failed to decode /policies response: %w", err)
	}

	return &policyResp, nil
}
