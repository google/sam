package main

import (
	"context"

	"github.com/multiformats/go-multiaddr"
)

type hubConnectionManager interface {
	IsConnected() bool
	HubPeerIDString() string
	LoadHubConfig() ([]byte, []string, error)
	ConnectAndAuthWithHub(ctx context.Context, addr multiaddr.Multiaddr) error
	LoadHubURL() (string, error)

	SaveHubConfig(pubKey []byte, addrs []string) error
}

// checkHubConnection monitors the connection to the hub and attempts to recover it if disconnected.
// It returns two booleans indicating the current state of the connection:
// - stable: true if the connection was already established and is healthy.
// - reconnected: true if the connection was lost but successfully recovered during this check.
//
// The recovery process follows these steps:
//  1. Connection Check: If already connected, return (stable=true, reconnected=false).
//  2. P2P Retry: If disconnected, attempt to reconnect using the known P2P multiaddresses stored locally.
//  3. HTTP Fallback: If P2P retries fail, fall back to HTTP discovery using the stored Hub URL to fetch
//     the new Hub addresses and Peer IDs, update the local config, and attempt to reconnect.
//  4. Total Failure: If all reconnection attempts fail, return (stable=false, reconnected=false).
func checkHubConnection(ctx context.Context, mgr hubConnectionManager) (stable bool, reconnected bool) {
	if mgr.IsConnected() {
		return true, false
	}

	logger.Warnf("[Monitor] Disconnected from Hub %s. Attempting to reconnect...", mgr.HubPeerIDString())

	var p2pAddrs []multiaddr.Multiaddr
	if _, storedAddrs, err := mgr.LoadHubConfig(); err == nil {
		for _, addrStr := range storedAddrs {
			if ma, err := multiaddr.NewMultiaddr(addrStr); err == nil {
				p2pAddrs = append(p2pAddrs, ma)
			}
		}
	}

	for _, addr := range p2pAddrs {
		if err := mgr.ConnectAndAuthWithHub(ctx, addr); err == nil {
			logger.Infof("[Monitor] Successfully reconnected to Hub via P2P.")
			return false, true
		}
	}

	hubURL, err := mgr.LoadHubURL()
	if err != nil || hubURL == "" {
		return false, false
	}

	logger.Infof("[Monitor] Reconnect P2P failed. Discovering hub info from %s...", hubURL)
	info, err := FetchHubInfo(ctx, hubURL)
	if err != nil || len(info.HubAddresses) == 0 {
		return false, false
	}

	var newHubAddrs []multiaddr.Multiaddr
	for _, addrStr := range info.HubAddresses {
		if ma, err := multiaddr.NewMultiaddr(addrStr); err == nil {
			newHubAddrs = append(newHubAddrs, ma)
		}
	}

	if len(newHubAddrs) == 0 {
		return false, false
	}

	if pubKeyBytes, _, err := mgr.LoadHubConfig(); err == nil {
		if saveErr := mgr.SaveHubConfig(pubKeyBytes, info.HubAddresses); saveErr != nil {
			logger.Errorf("[Monitor] Failed to save updated hub config: %v", saveErr)
		}
	}

	for _, addr := range newHubAddrs {
		if err := mgr.ConnectAndAuthWithHub(ctx, addr); err == nil {
			logger.Infof("[Monitor] Successfully reconnected to Hub via HTTP fallback.")
			return false, true
		}
	}

	return false, false
}
