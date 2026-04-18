package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"

	"sam/pkg/economy"
	"sam/pkg/identity"
	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

func newCallCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "call <peer-id|capability>",
		Short: "Execute an A2A task against a remote SAM agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCall(cmd.Context(), cfg, strings.TrimSpace(args[0]))
		},
	}

	f := cmd.Flags()
	f.StringVar(&cfg.callMessage, "message", "", "natural-language prompt sent to the remote agent")
	f.StringVar(&cfg.callBiscuit, "biscuit", "dev-biscuit", "Biscuit token sent in A2A call headers")
	f.Int64Var(&cfg.callAmount, "amount", 1, "micropayment amount sent in A2A call headers")
	f.StringVar(&cfg.callAsset, "asset", "sam-credit", "micropayment asset sent in A2A call headers")
	f.StringVar(&cfg.callNonce, "nonce", "", "optional micropayment nonce (auto-generated when empty)")
	f.DurationVar(&cfg.callTimeout, "timeout", 20*time.Second, "A2A call timeout")
	f.StringVar(&cfg.dryRun, "dry-run", "", "dry-run mode: 'client' (no network) or 'server' (skip A2A execute)")
	_ = cmd.MarkFlagRequired("message")

	return cmd
}

func runCall(parent context.Context, cfg *runConfig, targetArg string) error {
	if strings.TrimSpace(cfg.callMessage) == "" {
		return fmt.Errorf("--message is required")
	}
	if cfg.callAmount <= 0 {
		return fmt.Errorf("--amount must be positive")
	}
	if strings.TrimSpace(cfg.callAsset) == "" {
		return fmt.Errorf("--asset is required")
	}
	if cfg.callTimeout <= 0 {
		cfg.callTimeout = 20 * time.Second
	}

	// For dry-run=client mode, validate the request without network
	if cfg.dryRun == "client" {
		return runCallDryRunClient(cfg, targetArg)
	}

	node, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	ctx, cancel := context.WithTimeout(parent, cfg.callTimeout)
	defer cancel()

	target, capability, err := resolveCallTarget(ctx, node, targetArg)
	if err != nil {
		return err
	}

	vouch, err := loadLocalVouch()
	if err != nil {
		return err
	}

	observer, err := protocol.NewBoltObserverForFederation(cfg.federation)
	if err != nil {
		return fmt.Errorf("creating reputation observer: %w", err)
	}
	defer func() { _ = observer.Close() }()

	nonce := strings.TrimSpace(cfg.callNonce)
	if nonce == "" {
		nonce = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if capability == "" {
		capability = targetArg
	}
	requestJSON, err := buildCallRequest(cfg.callMessage)
	if err != nil {
		return err
	}

	resp, err := protocol.Execute(ctx, node.Host(), protocol.ExecuteRequest{
		Target:     target,
		Capability: capability,
		Vouch:      vouch,
		Biscuit:    cfg.callBiscuit,
		Payment: economy.Micropayment{
			Amount:     cfg.callAmount,
			Asset:      cfg.callAsset,
			Nonce:      nonce,
			Capability: capability,
		},
		MCPRequest: requestJSON,
	}, observer)
	if err != nil {
		return fmt.Errorf("A2A call failed: %w", err)
	}

	var out any
	if err := json.Unmarshal(resp, &out); err != nil {
		_, _ = os.Stdout.Write(append(resp, '\n'))
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func resolveCallTarget(ctx context.Context, node samnet.Node, targetArg string) (peer.AddrInfo, string, error) {
	targetArg = strings.TrimSpace(targetArg)
	if targetArg == "" {
		return peer.AddrInfo{}, "", fmt.Errorf("target peer ID or capability is required")
	}

	if pid, err := peer.Decode(targetArg); err == nil {
		return peer.AddrInfo{ID: pid, Addrs: node.Host().Peerstore().Addrs(pid)}, "", nil
	}

	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return peer.AddrInfo{}, "", fmt.Errorf("creating discovery service: %w", err)
	}
	peers, err := svc.DiscoverPeers(ctx, targetArg)
	if err != nil {
		return peer.AddrInfo{}, "", fmt.Errorf("discovering capability %q: %w", targetArg, err)
	}
	if len(peers) == 0 {
		return peer.AddrInfo{}, "", fmt.Errorf("no peers found for capability %q", targetArg)
	}
	return peers[0], targetArg, nil
}

func loadLocalVouch() (*identity.Vouch, error) {
	store, err := identity.DefaultCredentialStore()
	if err != nil {
		return nil, fmt.Errorf("opening credential store: %w", err)
	}
	defer func() { _ = store.Close() }()
	creds, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}
	if creds == nil || creds.Vouch == nil {
		return nil, fmt.Errorf("identity vouch not found; run 'sam identity login --hub <url>' first")
	}
	if creds.Vouch.IsExpired() {
		return nil, fmt.Errorf("stored identity vouch is expired; run login again")
	}
	return creds.Vouch, nil
}

func buildCallRequest(message string) (json.RawMessage, error) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "sam-call",
		"method":  "message",
		"params": map[string]any{
			"message": strings.TrimSpace(message),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encoding call payload: %w", err)
	}
	return json.RawMessage(payload), nil
}

// runCallDryRunClient validates a call request without network activity
func runCallDryRunClient(cfg *runConfig, targetArg string) error {
	if strings.TrimSpace(targetArg) == "" {
		return fmt.Errorf("target peer ID or capability is required")
	}

	nonce := strings.TrimSpace(cfg.callNonce)
	if nonce == "" {
		nonce = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	capability := targetArg

	// Build the call request structure
	callReq := map[string]any{
		"target":     targetArg,
		"capability": capability,
		"biscuit":    cfg.callBiscuit,
		"payment": map[string]any{
			"amount":     cfg.callAmount,
			"asset":      cfg.callAsset,
			"nonce":      nonce,
			"capability": capability,
		},
		"message": cfg.callMessage,
	}

	// Output format
	if cfg.outputFormat == "json" {
		return json.NewEncoder(os.Stdout).Encode(callReq)
	}

	// Default human-readable format
	data, _ := json.MarshalIndent(callReq, "", "  ")
	fmt.Println(string(data))
	return nil
}
