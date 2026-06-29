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
	"encoding/json"
	"fmt"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// catalogEntry mirrors internal/catalog.Entry's JSON (default Go field names).
type catalogEntry struct {
	Type   api.ServiceType
	Name   string
	PeerID string
}

// catalogEntriesToProviders parses the catalog's JSON result into providers.
func catalogEntriesToProviders(n *SamNode, raw, typeStr string) ([]*api.DiscoveredProvider, error) {
	var entries []catalogEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("catalog result unmarshal: %w", err)
	}
	out := []*api.DiscoveredProvider{}
	for _, e := range entries {
		// Skip self; guard nil Host so the mapper works in unit tests.
		if n.Host != nil && e.PeerID == n.Host.ID().String() {
			continue
		}
		out = append(out, &api.DiscoveredProvider{
			PeerId:        e.PeerID,
			LocalProxyUrl: n.localProxyURL(peer.ID(e.PeerID), typeStr, e.Name),
			SrvName:       e.Name,
		})
	}
	return out, nil
}

// findCatalogProvider returns a remembered catalog peer, discovering one if needed.
func (n *SamNode) findCatalogProvider(ctx context.Context, forceRefresh bool) (peer.ID, bool) {
	n.catalogMu.Lock()
	defer n.catalogMu.Unlock()
	if n.catalogPeer != "" && !forceRefresh {
		return n.catalogPeer, true
	}
	infos, err := n.FindProvidersByType(ctx, api.ServiceType_SERVICE_TYPE_CATALOG)
	if err != nil {
		logger.Warnf("[Catalog] provider lookup failed: %v", err)
		return "", false
	}
	for _, p := range infos {
		if p.ID == n.Host.ID() {
			continue
		}
		n.catalogPeer = p.ID
		return p.ID, true
	}
	n.catalogPeer = ""
	return "", false
}

// queryCatalog asks a catalog peer to resolve the request; returns (providers, true)
// only on a successful non-empty result. Retries once with a fresh peer on failure.
func (n *SamNode) queryCatalog(ctx context.Context, serviceType api.ServiceType, typeStr, serviceName string) ([]*api.DiscoveredProvider, bool) {
	for attempt := 0; attempt < 2; attempt++ {
		p, ok := n.findCatalogProvider(ctx, attempt > 0)
		if !ok {
			return nil, false
		}
		args := map[string]string{"type": typeStr}
		if serviceName != "" {
			args["name"] = serviceName
		}
		res, err := n.callMCPToolOnce(ctx, p, "catalog.query_catalog", args)
		if err != nil {
			logger.Warnf("[Catalog] query via %s failed: %v", p, err)
			continue
		}
		if res == nil || len(res.Content) == 0 {
			return nil, false
		}
		text, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			return nil, false
		}
		providers, err := catalogEntriesToProviders(n, text.Text, typeStr)
		if err != nil || len(providers) == 0 {
			return nil, false
		}
		logger.Infof("[Catalog] resolved %d providers via catalog %s", len(providers), p)
		return providers, true
	}
	return nil, false
}
