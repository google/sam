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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/announce"
	"github.com/google/sam/internal/catalog"
	"google.golang.org/protobuf/encoding/protojson"
)

type nodeClient struct {
	baseURL string
	token   string
	hc      *http.Client
}

func newNodeClient(baseURL, token string) *nodeClient {
	return &nodeClient{baseURL: baseURL, token: token, hc: &http.Client{}}
}

// serviceTypeStr maps ServiceType to the short query-param string.
func serviceTypeStr(t api.ServiceType) (string, error) {
	switch t {
	case api.ServiceType_SERVICE_TYPE_MCP:
		return "mcp", nil
	case api.ServiceType_SERVICE_TYPE_INFERENCE:
		return "inference", nil
	case api.ServiceType_SERVICE_TYPE_CATALOG:
		return "catalog", nil
	default:
		return "", fmt.Errorf("unsupported service type: %v", t)
	}
}

// bootstrap fetches discovered providers per type and upserts synthetic announces.
// Per-type failures are logged and skipped; remaining types are still processed.
func (c *nodeClient) bootstrap(ctx context.Context, store *catalog.Store, types []api.ServiceType) error {
	for _, t := range types {
		typeStr, err := serviceTypeStr(t)
		if err != nil {
			log.Printf("bootstrap: skip unknown type %v: %v", t, err)
			continue
		}
		url := c.baseURL + "/sam/service/discover?type=" + typeStr
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			log.Printf("bootstrap: build request for %s: %v", typeStr, err)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		resp, err := c.hc.Do(req)
		if err != nil {
			log.Printf("bootstrap: fetch %s: %v", typeStr, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			// surface auth/server errors instead of silently skipping
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			log.Printf("bootstrap: %s returned status %d: %s", typeStr, resp.StatusCode, strings.TrimSpace(string(snippet)))
			continue
		}
		var providers []*api.DiscoveredProvider
		if err := json.NewDecoder(resp.Body).Decode(&providers); err != nil {
			_ = resp.Body.Close()
			log.Printf("bootstrap: decode providers for %s: %v", typeStr, err)
			continue
		}
		_ = resp.Body.Close()
		for _, p := range providers {
			// No Addrs: discover doesn't return provider dial addrs. Bootstrap-only
			// entries carry empty Addrs until a live announce refreshes them (~1
			// reprovide cycle). Harmless today: consumers route by peer id via the
			// egress proxy, not Entry.Addrs. Fill from peerstore/DHT only if a
			// consumer ever dials Addrs directly.
			ann := &api.ServiceAnnounce{
				Type:   t,
				Name:   p.SrvName,
				PeerId: p.PeerId,
				TtlMs:  announce.TTL.Milliseconds(),
			}
			store.Upsert(ann, time.Now())
		}
	}
	return nil
}

// tail streams SSE announces from the node and upserts each into the store.
// It reconnects with a fixed backoff (on any exit, error or clean EOF) until ctx is done.
func (c *nodeClient) tail(ctx context.Context, store *catalog.Store) error {
	const backoff = 2 * time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.readSSEStream(ctx, store); err != nil && ctx.Err() == nil {
			log.Printf("tail: stream error: %v; reconnecting in %s", err, backoff)
		}
		// Always back off before reconnecting, whether stream ended cleanly or not.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// readSSEStream opens one SSE connection and processes events until EOF or ctx done.
func (c *nodeClient) readSSEStream(ctx context.Context, store *catalog.Store) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/sam/service/announce/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// surface auth/server errors; defer closes the body
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("announce stream returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue // skip event:/blank lines
		}
		payload := strings.TrimPrefix(line, "data: ")
		var ann api.ServiceAnnounce
		if err := protojson.Unmarshal([]byte(payload), &ann); err != nil {
			continue
		}
		store.Upsert(&ann, time.Now())
	}
	return scanner.Err()
}

// runSweeper calls store.Sweep on a ticker until ctx is done.
func runSweeper(ctx context.Context, store *catalog.Store, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			store.Sweep(now)
		}
	}
}

// runRewalk periodically calls bootstrap to reconcile entries missed via gossip.
func runRewalk(ctx context.Context, nc *nodeClient, store *catalog.Store, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := nc.bootstrap(ctx, store, []api.ServiceType{
				api.ServiceType_SERVICE_TYPE_MCP,
				api.ServiceType_SERVICE_TYPE_INFERENCE,
			}); err != nil && ctx.Err() == nil {
				log.Printf("rewalk: %v", err)
			}
		}
	}
}
