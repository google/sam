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

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"go.etcd.io/bbolt"

	internaldb "sam/internal/db"
	"sam/internal/testutils"
	"sam/pkg/economy"
	"sam/pkg/identity"
	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

const proxyRecordVersion = 1

func TestProxyTunnelLegacyFlowIntegration(t *testing.T) {
	testutils.Run(t, func(t *testing.T) {
		runProxyTunnelLegacyFlowIntegration(t)
	})
}

func TestProxyTunnelUnauthorizedBeforeDial(t *testing.T) {
	testutils.Run(t, func(t *testing.T) {
		runProxyTunnelUnauthorizedBeforeDial(t)
	})
}

func runProxyTunnelLegacyFlowIntegration(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpHome, ".config"))

	federation := "proxy-legacy"
	observer, err := protocol.NewBoltObserverForFederation(federation)
	if err != nil {
		t.Fatalf("creating observer: %v", err)
	}
	defer func() { _ = observer.Close() }()

	requestSeen := make(chan *http.Request, 1)
	bodySeen := make(chan []byte, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestSeen <- r.Clone(r.Context())
		bodySeen <- append([]byte(nil), body...)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend", "sam-provider")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backend.Close()

	providerNode, err := newProxyNode(0, nil)
	if err != nil {
		t.Fatalf("creating provider node: %v", err)
	}
	if err := providerNode.Start(ctx); err != nil {
		t.Fatalf("starting provider node: %v", err)
	}
	defer func() { _ = providerNode.Stop(context.Background()) }()

	tunnelSvc, err := protocol.NewHTTPTunnelService(
		providerNode.Host(),
		backend.URL,
		protocol.WithHTTPTunnelSkillGate(economy.NewBiscuitSkillGate(nil)),
	)
	if err != nil {
		t.Fatalf("creating tunnel service: %v", err)
	}
	defer tunnelSvc.Close()

	consumerNode, err := newProxyNode(0, providerBootstrap(providerNode))
	if err != nil {
		t.Fatalf("creating consumer node: %v", err)
	}
	if err := consumerNode.Start(ctx); err != nil {
		t.Fatalf("starting consumer node: %v", err)
	}
	defer func() { _ = consumerNode.Stop(context.Background()) }()

	providerInfo := peer.AddrInfo{ID: providerNode.PeerID(), Addrs: providerNode.Host().Addrs()}
	if err := connectProxyWithRetry(ctx, consumerNode, providerInfo); err != nil {
		t.Fatalf("connecting consumer->provider: %v", err)
	}

	vouch := identity.NewVouch(consumerNode.PeerID().String(), "test-issuer", "test-subject", map[string]string{"email": "test@example.com"}, 5*time.Minute)
	proxySrv := httptest.NewServer(proxyTunnelHandler(consumerNode, observer, "X-SAM-Target", "alice;allow_skill=risk-audit", vouch))
	defer proxySrv.Close()

	payload := []byte(`{"request":"through-proxy"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxySrv.URL+"/data.json?via=proxy", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("X-SAM-Target", providerNode.PeerID().String())
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("User-Agent", "curl/8.5.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace-ID", "trace-123")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading proxy response: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status code: got=%d body=%s", resp.StatusCode, string(respBody))
	}
	if got := resp.Header.Get("X-Backend"); got != "sam-provider" {
		t.Fatalf("expected X-Backend header to be preserved, got=%q", got)
	}
	if !strings.Contains(string(respBody), `"status":"ok"`) {
		t.Fatalf("unexpected response body: %s", string(respBody))
	}

	select {
	case backendReq := <-requestSeen:
		if backendReq.Method != http.MethodPost {
			t.Fatalf("backend method mismatch: got=%s", backendReq.Method)
		}
		if backendReq.URL.RequestURI() != "/data.json?via=proxy" {
			t.Fatalf("backend path mismatch: got=%s", backendReq.URL.RequestURI())
		}
		if got := backendReq.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization header not preserved: got=%q", got)
		}
		if got := backendReq.Header.Get("User-Agent"); got != "curl/8.5.0" {
			t.Fatalf("User-Agent header not preserved: got=%q", got)
		}
		if got := backendReq.Header.Get("X-Trace-ID"); got != "trace-123" {
			t.Fatalf("X-Trace-ID header not preserved: got=%q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("backend did not receive request")
	}

	select {
	case gotBody := <-bodySeen:
		if string(gotBody) != string(payload) {
			t.Fatalf("backend payload mismatch: got=%s", string(gotBody))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("backend body not captured")
	}

	repDBPath := filepath.Join(tmpHome, ".config", "sam", "federations", federation+".db")
	if err := observer.Close(); err != nil {
		t.Fatalf("closing observer: %v", err)
	}
	successes, failures, err := readProxyReputationCounts(repDBPath)
	if err != nil {
		t.Fatalf("reading reputation db: %v", err)
	}
	if successes == 0 {
		t.Fatalf("expected at least one success reputation record")
	}
	if failures != 0 {
		t.Fatalf("unexpected failure reputation records: %d", failures)
	}
}

func runProxyTunnelUnauthorizedBeforeDial(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer backend.Close()

	providerNode, err := newProxyNode(0, nil)
	if err != nil {
		t.Fatalf("creating provider node: %v", err)
	}
	if err := providerNode.Start(ctx); err != nil {
		t.Fatalf("starting provider node: %v", err)
	}
	defer func() { _ = providerNode.Stop(context.Background()) }()

	tunnelSvc, err := protocol.NewHTTPTunnelService(providerNode.Host(), backend.URL)
	if err != nil {
		t.Fatalf("creating tunnel service: %v", err)
	}
	defer tunnelSvc.Close()

	consumerNode, err := newProxyNode(0, providerBootstrap(providerNode))
	if err != nil {
		t.Fatalf("creating consumer node: %v", err)
	}
	if err := consumerNode.Start(ctx); err != nil {
		t.Fatalf("starting consumer node: %v", err)
	}
	defer func() { _ = consumerNode.Stop(context.Background()) }()

	proxySrv := httptest.NewServer(proxyTunnelHandler(consumerNode, protocol.NopObserver{}, "X-SAM-Target", "", nil))
	defer proxySrv.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxySrv.URL+"/blocked", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("X-SAM-Target", providerNode.PeerID().String())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected unauthorized, got=%d body=%s", resp.StatusCode, string(body))
	}
	if backendHits.Load() != 0 {
		t.Fatalf("expected no backend hits before authorization, got=%d", backendHits.Load())
	}
}

func proxyTunnelHandler(node samnet.Node, observer protocol.Observer, targetHeader, biscuit string, vouch *identity.Vouch) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if vouch == nil {
			http.Error(w, "unauthorized: local identity login required", http.StatusUnauthorized)
			return
		}

		targetArg := strings.TrimSpace(r.Header.Get(targetHeader))
		if targetArg == "" {
			http.Error(w, "missing target header", http.StatusBadRequest)
			return
		}
		targetID, err := peer.Decode(targetArg)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid target: %v", err), http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("reading body: %v", err), http.StatusBadRequest)
			return
		}

		headers := r.Header.Clone()
		headers.Del(targetHeader)

		start := time.Now()
		resp, err := protocol.TunnelHTTP(r.Context(), node.Host(), targetID, protocol.HTTPTunnelOpenRequest{
			Vouch:      vouch,
			Biscuit:    biscuit,
			Capability: "risk-audit",
			Request: protocol.HTTPTunnelRequest{
				Method:  r.Method,
				Path:    r.URL.RequestURI(),
				Headers: headers,
				Body:    body,
			},
		})
		if err != nil {
			observer.OnFailure(targetID.String(), protocol.FailureTypeLiveness)
			http.Error(w, fmt.Sprintf("tunnel request failed: %v", err), http.StatusBadGateway)
			return
		}
		if resp.Error != "" {
			observer.OnFailure(targetID.String(), protocol.FailureTypeRemote)
			status := resp.StatusCode
			if status == 0 {
				status = http.StatusBadGateway
			}
			http.Error(w, resp.Error, status)
			return
		}

		for key, vals := range resp.Headers {
			for _, val := range vals {
				w.Header().Add(key, val)
			}
		}
		status := resp.StatusCode
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(resp.Body)

		observer.OnSuccess(targetID.String(), time.Since(start))
	})
}

func providerBootstrap(node samnet.Node) []multiaddr.Multiaddr {
	addrs := node.Host().Addrs()
	if len(addrs) == 0 {
		return nil
	}
	return []multiaddr.Multiaddr{addrs[0].Encapsulate(multiaddr.StringCast("/p2p/" + node.PeerID().String()))}
}

func newProxyNode(port int, bootstrap []multiaddr.Multiaddr) (samnet.Node, error) {
	listen, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1", port))
	if err != nil {
		return nil, fmt.Errorf("building listen address: %w", err)
	}
	key, err := samnet.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating node key: %w", err)
	}
	return samnet.New(
		samnet.WithPrivateKey(key),
		samnet.WithListenAddrs(listen),
		samnet.WithBootstrapPeers(bootstrap...),
		samnet.WithDHTMode(samnet.DHTModeServer),
	)
}

func connectProxyWithRetry(ctx context.Context, node samnet.Node, pi peer.AddrInfo) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := node.Connect(ctx, pi); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return last
		case <-ticker.C:
		}
	}
}

func readProxyReputationCounts(path string) (int, int, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, 0, err
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = db.Close() }()

	type reputationRecord struct {
		PeerID    string `json:"peer_id"`
		OK        bool   `json:"ok"`
		LatencyMS int64  `json:"latency_ms,omitempty"`
		ErrorType string `json:"error_type,omitempty"`
	}

	codec := internaldb.JSONCodec{}
	successes := 0
	failures := 0
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(internaldb.BucketReputation))
		if bucket == nil {
			return fmt.Errorf("missing reputation bucket")
		}
		return bucket.ForEach(func(_ []byte, value []byte) error {
			var rec reputationRecord
			if err := codec.Unmarshal(value, proxyRecordVersion, &rec, nil); err != nil {
				return err
			}
			if rec.OK {
				successes++
			} else {
				failures++
			}
			return nil
		})
	})
	if err != nil {
		return 0, 0, err
	}
	return successes, failures, nil
}
