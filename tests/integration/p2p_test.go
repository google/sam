package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"sam/internal/testutils"
	"sam/pkg/economy"
	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

const (
	helperEnv      = "SAM_INTEGRATION_HELPER"
	helperRoleEnv  = "SAM_INTEGRATION_ROLE"
	helperInfoEnv  = "SAM_INTEGRATION_INFO_FILE"
	helperIPEnv    = "SAM_INTEGRATION_IP"
	helperPortEnv  = "SAM_INTEGRATION_PORT"
	providerRole   = "provider"
	consumerRole   = "consumer"
	providerIP     = "10.199.0.1"
	consumerIP     = "10.199.0.2"
	providerPort   = 4101
	consumerPort   = 4102
	validBiscuit   = "valid-biscuit"
	capabilityName = "agent.chat"
)

type providerInfo struct {
	PeerID    string `json:"peer_id"`
	Bootstrap string `json:"bootstrap"`
}

type roleProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func TestFirstContactP2P(t *testing.T) {
	if os.Getenv(helperEnv) == "1" {
		if err := runHelperRole(); err != nil {
			t.Fatalf("integration helper failed: %v", err)
		}
		return
	}

	testutils.Run(t, func(t *testing.T) {
		runFirstContact(t)
	}, syscall.CLONE_NEWNET)
}

func runFirstContact(t *testing.T) {
	tmpDir := t.TempDir()
	infoFile := filepath.Join(tmpDir, "provider.json")

	provider := startRoleProcess(t, providerRole, infoFile, providerIP, providerPort)
	defer stopRoleProcess(provider)

	consumer := startRoleProcess(t, consumerRole, infoFile, consumerIP, consumerPort)
	defer stopRoleProcess(consumer)

	configureVethPair(t, provider.cmd.Process.Pid, consumer.cmd.Process.Pid)

	if _, err := io.WriteString(provider.stdin, "start\n"); err != nil {
		t.Fatalf("starting provider helper: %v", err)
	}
	if _, err := io.WriteString(consumer.stdin, "start\n"); err != nil {
		t.Fatalf("starting consumer helper: %v", err)
	}

	if err := waitForProviderInfoFile(infoFile, 10*time.Second); err != nil {
		t.Fatalf("provider did not publish startup info: %v\nprovider stdout:\n%s\nprovider stderr:\n%s",
			err, provider.stdout.String(), provider.stderr.String())
	}

	waitRoleExit(t, consumer, 30*time.Second)

	if consumer.cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("consumer process failed\nstdout:\n%s\nstderr:\n%s", consumer.stdout.String(), consumer.stderr.String())
	}
}

func runHelperRole() error {
	reader := bufio.NewReader(os.Stdin)
	if _, err := reader.ReadString('\n'); err != nil {
		return fmt.Errorf("waiting for helper start signal: %w", err)
	}

	role := os.Getenv(helperRoleEnv)
	switch role {
	case providerRole:
		return runProviderRole()
	case consumerRole:
		return runConsumerRole()
	default:
		return fmt.Errorf("unknown helper role %q", role)
	}
}

func runProviderRole() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	port, err := parseHelperPort()
	if err != nil {
		return err
	}

	node, err := newNode(port, samnet.DHTModeServer, nil)
	if err != nil {
		return err
	}
	defer node.Stop(context.Background())

	if err := node.Start(ctx); err != nil {
		return fmt.Errorf("provider node start: %w", err)
	}

	providerAddr := fmt.Sprintf("/ip4/%s/udp/%d/quic-v1/p2p/%s", os.Getenv(helperIPEnv), port, node.PeerID())
	info := providerInfo{PeerID: node.PeerID().String(), Bootstrap: providerAddr}
	if err := writeProviderInfo(os.Getenv(helperInfoEnv), info); err != nil {
		return err
	}

	priv := node.Host().Peerstore().PrivKey(node.PeerID())
	card, err := protocol.NewAgentCard(
		node.PeerID(),
		[]string{capabilityName},
		[]protocol.MCPResource{{Name: "echo", Kind: "tool", Endpoint: "mcp://echo"}},
		priv,
	)
	if err != nil {
		return fmt.Errorf("provider card creation: %w", err)
	}

	publisher, err := protocol.NewPublisher(node)
	if err != nil {
		return fmt.Errorf("provider publisher: %w", err)
	}
	if err := publisher.Publish(ctx, card); err != nil {
		if err := publishWithRetry(ctx, publisher, card); err != nil {
			return fmt.Errorf("provider publish: %w", err)
		}
	}

	discovery, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return fmt.Errorf("provider discovery service: %w", err)
	}
	if err := discovery.RegisterLocalCard(card); err != nil {
		return fmt.Errorf("provider register local card: %w", err)
	}

	if _, err := protocol.NewMCPBridge(node.Host(), tokenVerifier{token: validBiscuit}, echoConnector{}); err != nil {
		return fmt.Errorf("provider bridge setup: %w", err)
	}

	// Keep the provider online while the consumer performs discovery and bridge calls.
	<-ctx.Done()
	return nil
}

func publishWithRetry(ctx context.Context, publisher *protocol.Publisher, card *protocol.AgentCard) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := publisher.Publish(ctx, card); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil { //nolint:staticcheck // lastErr is assigned only on error in the loop
				return fmt.Errorf("context ended before publish converged: %w", lastErr)
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func runConsumerRole() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	port, err := parseHelperPort()
	if err != nil {
		return err
	}

	info, err := waitProviderInfo(ctx, os.Getenv(helperInfoEnv))
	if err != nil {
		return err
	}
	bootstrap, err := multiaddr.NewMultiaddr(info.Bootstrap)
	if err != nil {
		return fmt.Errorf("parsing bootstrap address: %w", err)
	}
	providerID, err := peer.Decode(info.PeerID)
	if err != nil {
		return fmt.Errorf("decoding provider peer ID: %w", err)
	}
	providerAddrInfo, err := peer.AddrInfoFromP2pAddr(bootstrap)
	if err != nil {
		return fmt.Errorf("building provider addr info from bootstrap: %w", err)
	}

	// In a two-node isolated mesh, both peers need DHT server participation so
	// provider records can be stored and later discovered.
	node, err := newNode(port, samnet.DHTModeServer, []multiaddr.Multiaddr{bootstrap})
	if err != nil {
		return err
	}
	defer node.Stop(context.Background())

	if err := node.Start(ctx); err != nil {
		return fmt.Errorf("consumer node start: %w", err)
	}
	if err := connectWithRetry(ctx, node, *providerAddrInfo); err != nil {
		return fmt.Errorf("connecting to bootstrap provider: %w", err)
	}

	discovery, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return fmt.Errorf("consumer discovery service: %w", err)
	}

	peerIDs, err := discoverAndConnectWithRetry(ctx, discovery, capabilityName)
	if err != nil {
		return err
	}

	_, discoverErr := discoverCardsWithRetry(ctx, discovery, capabilityName)
	if discoverErr != nil {
		return discoverErr
	}
	_ = peerIDs

	bridge, err := protocol.NewMCPBridge(node.Host(), allowVerifier{}, echoConnector{})
	if err != nil {
		return fmt.Errorf("consumer bridge setup: %w", err)
	}

	if err := expectDeniedBridge(ctx, bridge, providerID); err != nil {
		return err
	}
	if err := expectAllowedBridge(ctx, bridge, providerID); err != nil {
		return err
	}

	return nil
}

func discoverAndConnectWithRetry(ctx context.Context, svc *protocol.DiscoveryService, capability string) ([]peer.ID, error) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		ids, err := svc.DiscoverAndConnect(ctx, capability)
		if len(ids) > 0 {
			return ids, nil
		}
		if err != nil {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("no peers connected for capability %q: %w", capability, lastErr)
			}
			return nil, fmt.Errorf("no peers connected for capability %q: %w", capability, ctx.Err())
		case <-ticker.C:
		}
	}
}

func connectWithRetry(ctx context.Context, node samnet.Node, pi peer.AddrInfo) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := node.Connect(ctx, pi); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func discoverCardsWithRetry(ctx context.Context, svc *protocol.DiscoveryService, capability string) ([]*protocol.AgentCard, error) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		cards, err := svc.Discover(ctx, capability)
		if err == nil && len(cards) > 0 {
			return cards, nil
		}
		if err != nil {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("discovering cards for capability %q: %w", capability, lastErr)
			}
			return nil, fmt.Errorf("expected at least one discovered card for capability %q", capability)
		case <-ticker.C:
		}
	}
}

func expectDeniedBridge(ctx context.Context, bridge *protocol.MCPBridge, providerID peer.ID) error {
	stream, err := bridge.Open(ctx, providerID, protocol.BridgeOpenRequest{
		BiscuitToken: "invalid-biscuit",
		Amount:       1,
		Asset:        "sam-credit",
		Nonce:        "nonce-denied",
		Capability:   capabilityName,
	})
	if err != nil {
		return fmt.Errorf("opening denied bridge stream: %w", err)
	}
	defer stream.Close()

	buf := make([]byte, 1024)
	n, readErr := stream.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("reading denied bridge response: %w", readErr)
	}
	if !strings.Contains(string(buf[:n]), economy.ErrVerifierDeniedRequest.Error()) {
		return fmt.Errorf("expected denied verifier response, got %q", string(buf[:n]))
	}
	return nil
}

func expectAllowedBridge(ctx context.Context, bridge *protocol.MCPBridge, providerID peer.ID) error {
	stream, err := bridge.Open(ctx, providerID, protocol.BridgeOpenRequest{
		BiscuitToken: validBiscuit,
		Amount:       2,
		Asset:        "sam-credit",
		Nonce:        "nonce-allowed",
		Capability:   capabilityName,
	})
	if err != nil {
		return fmt.Errorf("opening allowed bridge stream: %w", err)
	}
	defer stream.Close()

	payload := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"handshake\"}\n")
	if _, err := stream.Write(payload); err != nil {
		return fmt.Errorf("writing allowed bridge payload: %w", err)
	}

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, received); err != nil {
		return fmt.Errorf("reading allowed bridge response: %w", err)
	}
	if string(received) != string(payload) {
		return fmt.Errorf("expected echo payload %q, got %q", string(payload), string(received))
	}
	return nil
}

func newNode(port int, mode samnet.DHTMode, bootstrap []multiaddr.Multiaddr) (samnet.Node, error) {
	listen, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port))
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
		samnet.WithDHTMode(mode),
	)
}

func writeProviderInfo(path string, info providerInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating provider info file: %w", err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(info); err != nil {
		return fmt.Errorf("encoding provider info: %w", err)
	}
	return nil
}

func waitProviderInfo(ctx context.Context, path string) (providerInfo, error) {
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var info providerInfo
			if unmarshalErr := json.Unmarshal(data, &info); unmarshalErr != nil {
				return providerInfo{}, fmt.Errorf("decoding provider info: %w", unmarshalErr)
			}
			return info, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return providerInfo{}, fmt.Errorf("reading provider info: %w", err)
		}
		select {
		case <-ctx.Done():
			return providerInfo{}, fmt.Errorf("waiting for provider info: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitForProviderInfoFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func parseHelperPort() (int, error) {
	portRaw := strings.TrimSpace(os.Getenv(helperPortEnv))
	if portRaw == "" {
		return 0, fmt.Errorf("missing %s", helperPortEnv)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 {
		return 0, fmt.Errorf("invalid helper port %q", portRaw)
	}
	return port, nil
}

func startRoleProcess(t *testing.T, role, infoFile, ip string, port int) *roleProcess {
	t.Helper()

	proc := &roleProcess{}
	cmd := exec.Command(os.Args[0], "-test.run=TestFirstContactP2P$", "-test.v=true")
	cmd.Env = append(os.Environ(),
		helperEnv+"=1",
		helperRoleEnv+"="+role,
		helperInfoEnv+"="+infoFile,
		helperIPEnv+"="+ip,
		helperPortEnv+"="+strconv.Itoa(port),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("creating %s stdin pipe: %v", role, err)
	}
	proc.stdin = stdin
	cmd.Stdout = &proc.stdout
	cmd.Stderr = &proc.stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s process: %v", role, err)
	}
	proc.cmd = cmd
	return proc
}

func stopRoleProcess(proc *roleProcess) {
	if proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return
	}
	_ = proc.stdin.Close()
	_ = proc.cmd.Process.Kill()
	_, _ = proc.cmd.Process.Wait()
}

func waitRoleExit(t *testing.T, proc *roleProcess, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- proc.cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("role process wait failed: %v\nstdout:\n%s\nstderr:\n%s", err, proc.stdout.String(), proc.stderr.String())
		}
	case <-time.After(timeout):
		t.Fatalf("role process timed out\nstdout:\n%s\nstderr:\n%s", proc.stdout.String(), proc.stderr.String())
	}
}

func configureVethPair(t *testing.T, providerPID, consumerPID int) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "samveth-p"},
		PeerName:  "samveth-c",
	}); err != nil {
		t.Fatalf("creating veth pair: %v", err)
	}

	providerLink, err := netlink.LinkByName("samveth-p")
	if err != nil {
		t.Fatalf("finding provider veth: %v", err)
	}
	consumerLink, err := netlink.LinkByName("samveth-c")
	if err != nil {
		t.Fatalf("finding consumer veth: %v", err)
	}

	if err := netlink.LinkSetNsPid(providerLink, providerPID); err != nil {
		t.Fatalf("moving provider veth to netns pid %d: %v", providerPID, err)
	}
	if err := netlink.LinkSetNsPid(consumerLink, consumerPID); err != nil {
		t.Fatalf("moving consumer veth to netns pid %d: %v", consumerPID, err)
	}

	configureLinkInNetNS(t, providerPID, "samveth-p", providerIP+"/24")
	configureLinkInNetNS(t, consumerPID, "samveth-c", consumerIP+"/24")
}

func configureLinkInNetNS(t *testing.T, pid int, linkName, cidr string) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalNS, err := netns.Get()
	if err != nil {
		t.Fatalf("getting current netns: %v", err)
	}
	defer originalNS.Close()

	targetNS, err := netns.GetFromPid(pid)
	if err != nil {
		t.Fatalf("getting target netns for pid %d: %v", pid, err)
	}
	defer targetNS.Close()

	if err := netns.Set(targetNS); err != nil {
		t.Fatalf("entering netns for pid %d: %v", pid, err)
	}
	defer func() {
		if err := netns.Set(originalNS); err != nil {
			t.Fatalf("restoring original netns: %v", err)
		}
	}()

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("getting loopback in netns pid %d: %v", pid, err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bringing loopback up in netns pid %d: %v", pid, err)
	}

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		t.Fatalf("getting link %s in netns pid %d: %v", linkName, pid, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parsing cidr %s: %v", cidr, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("assigning addr %s to %s in pid %d: %v", cidr, linkName, pid, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bringing link %s up in netns pid %d: %v", linkName, pid, err)
	}
}

type tokenVerifier struct {
	token string
}

func (v tokenVerifier) Verify(_ context.Context, req economy.VerifyRequest) (*economy.VerifyDecision, error) {
	if req.Token != v.token {
		return nil, fmt.Errorf("invalid biscuit token")
	}
	return &economy.VerifyDecision{Subject: "peer:test"}, nil
}

type allowVerifier struct{}

func (allowVerifier) Verify(_ context.Context, _ economy.VerifyRequest) (*economy.VerifyDecision, error) {
	return &economy.VerifyDecision{Subject: "peer:test"}, nil
}

type echoConnector struct{}

func (echoConnector) Open(context.Context) (mcp.Transport, error) {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := b.Read(buf)
			if n > 0 {
				if _, werr := b.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return &mcp.IOTransport{Reader: a, Writer: a}, nil
}
