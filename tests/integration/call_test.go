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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"go.etcd.io/bbolt"

	internaldb "sam/internal/db"
	"sam/internal/testutils"
	"sam/pkg/economy"
	"sam/pkg/identity"
	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

const (
	callHelperEnv      = "SAM_CALL_HELPER"
	callRoleEnv        = "SAM_CALL_ROLE"
	callInfoEnv        = "SAM_CALL_INFO_FILE"
	callRepDBEnv       = "SAM_CALL_REPUTATION_DB"
	callProviderPIDEnv = "SAM_CALL_PROVIDER_PID"
	callRoleProvider   = "provider"
	callRoleConsumer   = "consumer"
	callCapability     = "weather-bot"
	callRecordVersion  = 1
)

type callPeerInfo struct {
	PeerID    string `json:"peer_id"`
	Bootstrap string `json:"bootstrap"`
}

type callRoleProcess struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func TestA2ACallIntegration(t *testing.T) {
	if os.Getenv(callHelperEnv) == "1" {
		if err := runCallRole(); err != nil {
			t.Fatalf("call helper failed: %v", err)
		}
		return
	}

	testutils.Run(t, func(t *testing.T) {
		runCallIntegration(t)
	})
}

func runCallIntegration(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()
	infoFile := filepath.Join(tmpDir, "provider.json")
	repDB := filepath.Join(tmpDir, "reputation.db")

	provider := startCallRoleProcess(t, callRoleProvider, map[string]string{
		callInfoEnv: infoFile,
	})
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("provider stdout:\n%s\nprovider stderr:\n%s", provider.stdout.String(), provider.stderr.String())
		}
	})
	defer stopCallRoleProcess(provider)

	if err := waitForCallInfoFile(infoFile, 15*time.Second); err != nil {
		t.Fatalf("provider did not write info file in time: %v\nprovider stdout:\n%s\nprovider stderr:\n%s",
			err, provider.stdout.String(), provider.stderr.String())
	}

	consumer := startCallRoleProcess(t, callRoleConsumer, map[string]string{
		callInfoEnv:        infoFile,
		callRepDBEnv:       repDB,
		callProviderPIDEnv: strconv.Itoa(provider.cmd.Process.Pid),
	})
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("consumer stdout:\n%s\nconsumer stderr:\n%s", consumer.stdout.String(), consumer.stderr.String())
		}
	})
	defer stopCallRoleProcess(consumer)

	waitCallRoleExit(t, consumer, 30*time.Second)
	if consumer.cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("consumer process failed\nstdout:\n%s\nstderr:\n%s",
			consumer.stdout.String(), consumer.stderr.String())
	}

	db, err := bbolt.Open(repDB, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("opening reputation DB: %v", err)
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
	livenessFailures := 0
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(internaldb.BucketReputation))
		if bucket == nil {
			return fmt.Errorf("missing reputation bucket")
		}
		return bucket.ForEach(func(_ []byte, value []byte) error {
			var rec reputationRecord
			if err := codec.Unmarshal(value, callRecordVersion, &rec, nil); err != nil {
				return err
			}
			if rec.OK {
				successes++
			}
			if !rec.OK && strings.EqualFold(rec.ErrorType, protocol.FailureTypeLiveness) {
				livenessFailures++
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("reading reputation records: %v", err)
	}
	if successes == 0 {
		t.Fatalf("expected at least one success interaction")
	}
	if livenessFailures == 0 {
		t.Fatalf("expected at least one liveness failure interaction")
	}
}

func runCallRole() error {
	switch os.Getenv(callRoleEnv) {
	case callRoleProvider:
		return runCallProviderRole()
	case callRoleConsumer:
		return runCallConsumerRole()
	default:
		return fmt.Errorf("unknown call role %q", os.Getenv(callRoleEnv))
	}
}

func runCallProviderRole() error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	node, err := newCallNode(0, nil)
	if err != nil {
		return err
	}
	if err := node.Start(ctx); err != nil {
		return fmt.Errorf("provider node start: %w", err)
	}
	// In a subprocess role, fire Stop asynchronously so the process can exit
	// promptly; the OS will clean up resources when the process terminates.
	defer func() {
		go func() { _ = node.Stop(context.Background()) }()
	}()

	// Register the A2A handler BEFORE writing the info file so the consumer
	// cannot connect and attempt Execute before the protocol is ready.
	a2aSvc, err := protocol.NewA2AService(node.Host(), delayedResponseConnector{delay: 1500 * time.Millisecond}, protocol.NopObserver{})
	if err != nil {
		return fmt.Errorf("provider A2A service setup: %w", err)
	}
	defer a2aSvc.Close()

	// Derive the bootstrap address from the actual listen addresses assigned
	// by the OS (we bound to port 0 to avoid fixed-port conflicts).
	// Filter to the first QUIC address to avoid picking up relay/circuit addrs.
	var quicAddr multiaddr.Multiaddr
	for _, a := range node.Host().Network().ListenAddresses() {
		s := a.String()
		if strings.Contains(s, "udp") && strings.Contains(s, "quic") {
			quicAddr = a
			break
		}
	}
	if quicAddr == nil {
		return fmt.Errorf("provider has no QUIC listen address after start; addrs: %v",
			node.Host().Network().ListenAddresses())
	}
	bootstrapAddr := quicAddr.String() + "/p2p/" + node.PeerID().String()
	if err := writeCallPeerInfo(os.Getenv(callInfoEnv), callPeerInfo{
		PeerID:    node.PeerID().String(),
		Bootstrap: bootstrapAddr,
	}); err != nil {
		return err
	}

	priv := node.Host().Peerstore().PrivKey(node.PeerID())
	card, err := protocol.NewAgentCard(
		node.PeerID(),
		[]string{callCapability},
		[]protocol.MCPResource{{Name: "weather", Kind: "tool", Endpoint: "mcp://weather"}},
		priv,
	)
	if err != nil {
		return fmt.Errorf("provider card creation: %w", err)
	}

	pub, err := protocol.NewPublisher(node)
	if err != nil {
		return fmt.Errorf("provider publisher: %w", err)
	}
	if err := publishCallWithRetry(ctx, pub, card); err != nil {
		return fmt.Errorf("provider publish: %w", err)
	}

	discovery, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return fmt.Errorf("provider discovery service: %w", err)
	}
	if err := discovery.RegisterLocalCard(card); err != nil {
		return fmt.Errorf("provider register card: %w", err)
	}

	<-ctx.Done()
	return nil
}

func runCallConsumerRole() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	providerPID, err := strconv.Atoi(os.Getenv(callProviderPIDEnv))
	if err != nil || providerPID <= 0 {
		return fmt.Errorf("invalid provider pid: %q", os.Getenv(callProviderPIDEnv))
	}

	info, err := waitCallPeerInfo(ctx, os.Getenv(callInfoEnv))
	if err != nil {
		return err
	}
	bootstrap, err := multiaddr.NewMultiaddr(info.Bootstrap)
	if err != nil {
		return fmt.Errorf("parsing bootstrap addr: %w", err)
	}
	providerID, err := peer.Decode(info.PeerID)
	if err != nil {
		return fmt.Errorf("decoding provider peer ID: %w", err)
	}
	providerAddrInfo, err := peer.AddrInfoFromP2pAddr(bootstrap)
	if err != nil {
		return fmt.Errorf("building provider addr info: %w", err)
	}

	node, err := newCallNode(0, []multiaddr.Multiaddr{bootstrap})
	if err != nil {
		return err
	}
	if err := node.Start(ctx); err != nil {
		return fmt.Errorf("consumer node start: %w", err)
	}
	// In a subprocess role, fire Stop asynchronously so the process can exit
	// promptly; the OS will clean up resources when the process terminates.
	defer func() {
		go func() { _ = node.Stop(context.Background()) }()
	}()

	if err := connectCallWithRetry(ctx, node, *providerAddrInfo); err != nil {
		return fmt.Errorf("connecting to provider bootstrap: %w", err)
	}

	// For call execution reliability in isolated namespaces, use the provider peer
	// directly after bootstrap connection instead of waiting for DHT convergence.
	target := peer.AddrInfo{ID: providerID, Addrs: node.Host().Peerstore().Addrs(providerID)}

	observer, err := protocol.NewBoltObserver(os.Getenv(callRepDBEnv))
	if err != nil {
		return fmt.Errorf("creating bolt observer: %w", err)
	}
	defer func() { _ = observer.Close() }()

	vouch := identity.NewVouch(node.PeerID().String(), "self", "test-subject", map[string]string{"name": "consumer"}, time.Hour)
	req := protocol.ExecuteRequest{
		Target:     target,
		Capability: callCapability,
		Vouch:      vouch,
		Biscuit:    "integration-biscuit",
		Payment: economy.Micropayment{
			Amount:     1,
			Asset:      "sam-credit",
			Nonce:      "nonce-success",
			Capability: callCapability,
		},
		MCPRequest: []byte(`{"jsonrpc":"2.0","id":"sam-call","method":"message","params":{"message":"weather"}}`),
	}

	if _, err := protocol.Execute(ctx, node.Host(), req, observer); err != nil {
		return fmt.Errorf("expected initial call success, got: %w", err)
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = syscall.Kill(providerPID, syscall.SIGKILL)
	}()

	req.Payment.Nonce = "nonce-failure"
	failCtx, failCancel := context.WithTimeout(ctx, 5*time.Second)
	defer failCancel()
	if _, err := protocol.Execute(failCtx, node.Host(), req, observer); err == nil {
		return fmt.Errorf("expected second call to fail after provider kill")
	}

	return nil
}

func newCallNode(port int, bootstrap []multiaddr.Multiaddr) (samnet.Node, error) {
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

func publishCallWithRetry(ctx context.Context, pub *protocol.Publisher, card *protocol.AgentCard) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := pub.Publish(ctx, card); err == nil {
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

func connectCallWithRetry(ctx context.Context, node samnet.Node, pi peer.AddrInfo) error {
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

func writeCallPeerInfo(path string, info callPeerInfo) error {
	if path == "" {
		return fmt.Errorf("%s is required", callInfoEnv)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating info directory: %w", err)
	}
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("encoding peer info: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func waitCallPeerInfo(ctx context.Context, path string) (callPeerInfo, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var info callPeerInfo
			if err := json.Unmarshal(data, &info); err == nil && info.PeerID != "" {
				return info, nil
			}
		}
		select {
		case <-ctx.Done():
			return callPeerInfo{}, fmt.Errorf("waiting for provider info file: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForCallInfoFile(path string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := waitCallPeerInfo(ctx, path)
	return err
}

func startCallRoleProcess(t *testing.T, role string, env map[string]string) *callRoleProcess {
	t.Helper()
	p := &callRoleProcess{}
	cmd := exec.Command(os.Args[0], "-test.run=TestA2ACallIntegration$", "-test.v=true")
	cmd.Env = append(os.Environ(), callHelperEnv+"=1", callRoleEnv+"="+role)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout = &p.stdout
	cmd.Stderr = &p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s role process: %v", role, err)
	}
	p.cmd = cmd
	return p
}

func waitCallRoleExit(t *testing.T, p *callRoleProcess, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("role process exited with error: %v", err)
		}
	case <-time.After(timeout):
		t.Logf("stdout:\n%s\nstderr:\n%s", p.stdout.String(), p.stderr.String())
		t.Fatalf("role process did not exit in %s", timeout)
	}
}

func stopCallRoleProcess(p *callRoleProcess) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

type delayedResponseConnector struct {
	delay time.Duration
}

func (c delayedResponseConnector) Open(context.Context) (mcp.Transport, error) {
	return delayedResponseTransport(c), nil
}

type delayedResponseTransport struct {
	delay time.Duration
}

func (t delayedResponseTransport) Connect(context.Context) (mcp.Connection, error) {
	msg, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":"sam-call","result":{"content":"sunny"}}`))
	if err != nil {
		return nil, err
	}
	return &delayedResponseConn{delay: t.delay, response: msg}, nil
}

type delayedResponseConn struct {
	delay    time.Duration
	response jsonrpc.Message
}

func (c *delayedResponseConn) Read(context.Context) (jsonrpc.Message, error) {
	time.Sleep(c.delay)
	return c.response, nil
}

func (c *delayedResponseConn) Write(context.Context, jsonrpc.Message) error {
	return nil
}

func (c *delayedResponseConn) Close() error {
	return nil
}

func (c *delayedResponseConn) SessionID() string {
	return "integration-session"
}
