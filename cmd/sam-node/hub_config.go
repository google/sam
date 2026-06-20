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
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// FetchHubInfo retrieves the latest configuration from the Hub's /info endpoint.
func FetchHubInfo(ctx context.Context, hubURL string) (*api.HubInfoResponse, error) {
	if !strings.HasPrefix(hubURL, "http://") && !strings.HasPrefix(hubURL, "https://") {
		hubURL = "https://" + hubURL
	}
	hubURL = strings.TrimSuffix(hubURL, "/")

	urlStr := hubURL + "/info"
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
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub returned status %s: %s", resp.Status, string(body))
	}

	var info api.HubInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to decode /info response: %w", err)
	}

	return &info, nil
}

// SyncHubConfig loads the hub configuration from the store, attempts to refresh it
// via HTTP from the hub, and updates the store if successful.
// It returns the hub public key and the latest multiaddresses.
func SyncHubConfig(ctx context.Context, s *Store) ([]byte, []multiaddr.Multiaddr, error) {
	pubKey, storedAddrsStr, err := s.LoadHubConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load hub config from store: %w", err)
	}

	hubURL, err := s.LoadHubURL()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load hub URL from store: %w", err)
	}
	var hubAddrs []multiaddr.Multiaddr

	// Parse stored addresses
	for _, addrStr := range storedAddrsStr {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("Failed to parse stored hub address %q: %v", addrStr, err)
			continue
		}
		hubAddrs = append(hubAddrs, ma)
	}

	// Fallback for legacy databases: extract URL from multiaddr
	if hubURL == "" && len(hubAddrs) > 0 {
		for _, addr := range hubAddrs {
			if val, err := addr.ValueForProtocol(multiaddr.P_DNS4); err == nil {
				hubURL = "https://" + val
				break
			}
			if val, err := addr.ValueForProtocol(multiaddr.P_DNSADDR); err == nil {
				hubURL = "https://" + val
				break
			}
		}
		if hubURL != "" {
			logger.Infof("Extracted legacy hub URL from multiaddrs: %s", hubURL)
		}
	}

	// If we have a URL, fetch the latest info
	if hubURL != "" {
		logger.Infof("Fetching latest hub addresses via HTTP from %s...", hubURL)
		info, err := FetchHubInfo(ctx, hubURL)
		if err != nil {
			logger.Warnf("Failed to fetch updated addresses via HTTP (using cached): %v", err)
		} else if len(info.HubAddresses) > 0 {
			logger.Infof("Discovered latest hub addresses: %v", info.HubAddresses)
			var newHubAddrs []multiaddr.Multiaddr
			for _, addrStr := range info.HubAddresses {
				ma, parseErr := multiaddr.NewMultiaddr(addrStr)
				if parseErr != nil {
					logger.Warnf("Failed to parse discovered hub address %q: %v", addrStr, parseErr)
					continue
				}
				newHubAddrs = append(newHubAddrs, ma)
			}
			if len(newHubAddrs) > 0 {
				hubAddrs = newHubAddrs
				if len(pubKey) > 0 {
					if saveErr := s.SaveHubConfig(pubKey, info.HubAddresses); saveErr != nil {
						logger.Errorf("Failed to save updated hub config to store: %v", saveErr)
					}
				}
			}
		}
	}

	return pubKey, hubAddrs, nil
}
