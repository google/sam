package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"sam/pkg/economy"
	"sam/pkg/protocol"
)

func newPublishMCPCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Expose a local MCP endpoint via libp2p and publish its agent card",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPublishMCP(cmd.Context(), cfg)
		},
	}
	cmd.Flags().IntVar(&cfg.mcpPort, "port", 0, "local TCP port serving the MCP JSON-RPC endpoint")
	_ = cmd.MarkFlagRequired("port")
	_ = cmd.MarkPersistentFlagRequired("capability")
	return cmd
}

func runPublishMCP(parent context.Context, cfg *runConfig) error {
	if len(cfg.capabilities) == 0 {
		return fmt.Errorf("at least one --capability is required")
	}
	if cfg.mcpPort <= 0 {
		return fmt.Errorf("--port must be a positive integer")
	}

	node, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	priv := node.Host().Peerstore().PrivKey(node.PeerID())
	if priv == nil {
		return fmt.Errorf("local node private key unavailable")
	}

	resource := protocol.MCPResource{
		Name:     strings.TrimSpace(cfg.resourceName),
		Kind:     strings.TrimSpace(cfg.resourceKind),
		Endpoint: fmt.Sprintf("http://127.0.0.1:%d", cfg.mcpPort),
	}
	card, err := protocol.NewAgentCard(node.PeerID(), cfg.capabilities, []protocol.MCPResource{resource}, priv)
	if err != nil {
		return fmt.Errorf("building agent card: %w", err)
	}

	connector := &httpMCPConnector{
		client: &http.Client{Timeout: 30 * time.Second},
		addr:   fmt.Sprintf("http://127.0.0.1:%d", cfg.mcpPort),
	}
	if _, err := protocol.NewMCPBridge(node.Host(), economy.AllowAllVerifier{}, connector); err != nil {
		return fmt.Errorf("creating MCP bridge: %w", err)
	}

	pub, err := protocol.NewPublisher(node)
	if err != nil {
		return fmt.Errorf("creating publisher: %w", err)
	}
	if err := publishLoop(parent, pub, card, cfg.republishEvery); err != nil {
		return fmt.Errorf("publishing agent card: %w", err)
	}

	if err := json.NewEncoder(os.Stdout).Encode(card); err != nil {
		return fmt.Errorf("encoding published card: %w", err)
	}

	slog.Default().Info("MCP bridge published",
		"peer_id", node.PeerID(),
		"mcp_port", cfg.mcpPort,
		"capabilities", cfg.capabilities,
	)
	return waitForShutdown(parent, cfg.runFor)
}

// httpMCPConnector dials a local HTTP MCP server and returns an IOTransport
// backed by the HTTP request/response body pair.
type httpMCPConnector struct {
	client *http.Client
	addr   string // e.g. "http://127.0.0.1:8080"
}

// Open establishes a streaming JSON-RPC connection to the local MCP server.
func (c *httpMCPConnector) Open(ctx context.Context) (mcp.Transport, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+"/mcp", pr)
	if err != nil {
		return nil, fmt.Errorf("building MCP HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		_ = pw.Close()
		return nil, fmt.Errorf("connecting to local MCP server at %s: %w", c.addr, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("local MCP server returned %s", resp.Status)
	}
	return &mcp.IOTransport{Reader: resp.Body, Writer: pw}, nil
}
