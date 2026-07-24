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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func buildBinary(t *testing.T, pkgPath string) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), filepath.Base(pkgPath))
	cmd := exec.Command("go", "build", "-o", out, pkgPath)
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s failed: %v\n%s", pkgPath, err, string(output))
	}
	return out
}

func runCommand(
	t *testing.T,
	cwd string,
	timeout time.Duration,
	env []string,
	stdin string,
	name string,
	args ...string,
) (string, string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	tmpBin := filepath.Join(t.TempDir(), "bin")
	_ = os.MkdirAll(tmpBin, 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "xdg-open"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "open"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	var finalEnv []string
	finalEnv = append(finalEnv, "BROWSER=echo")
	for _, e := range append(os.Environ(), env...) {
		if !strings.HasPrefix(e, "SSH_CLIENT=") && !strings.HasPrefix(e, "SSH_TTY=") {
			finalEnv = append(finalEnv, e)
		}
	}
	for i, e := range finalEnv {
		if strings.HasPrefix(e, "PATH=") {
			finalEnv[i] = "PATH=" + tmpBin + string(os.PathListSeparator) + e[5:]
		}
	}
	cmd.Env = finalEnv
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout.String(), stderr.String(), context.DeadlineExceeded
	}
	return stdout.String(), stderr.String(), err
}

type interceptorWriter struct {
	w       io.Writer
	buf     *bytes.Buffer
	handled bool
}

func (iw *interceptorWriter) Write(p []byte) (n int, err error) {
	n, err = iw.w.Write(p)
	iw.buf.Write(p)
	if !iw.handled {
		s := iw.buf.String()
		if strings.Contains(s, "redirect_uri=") && strings.Contains(s, "state=") {
			iw.handled = true
			go func() {
				// Parse URL from the buffer to extract state and redirect_uri
				// The URL is printed like: "  http://...redirect_uri=...&state=..."
				lines := strings.Split(s, "\n")
				for _, line := range lines {
					if strings.Contains(line, "redirect_uri=") {
						parts := strings.Split(strings.TrimSpace(line), " ")
						for _, p := range parts {
							if strings.HasPrefix(p, "http") {
								u, err := url.Parse(p)
								if err == nil {
									redirectURI := u.Query().Get("redirect_uri")
									state := u.Query().Get("state")
									if redirectURI != "" && state != "" {
										time.Sleep(100 * time.Millisecond)
										_, _ = http.Get(redirectURI + "?code=dev_code_123&state=" + state)
									}
								}
							}
						}
					}
				}
			}()
		}
	}
	return n, err
}

func runCommandWithCallback(
	t *testing.T,
	cwd string,
	timeout time.Duration,
	env []string,
	stdin string,
	name string,
	args ...string,
) (string, string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	tmpBin := filepath.Join(t.TempDir(), "bin")
	_ = os.MkdirAll(tmpBin, 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "xdg-open"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "open"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	var finalEnv []string
	finalEnv = append(finalEnv, "BROWSER=echo")
	for _, e := range append(os.Environ(), env...) {
		if !strings.HasPrefix(e, "SSH_CLIENT=") && !strings.HasPrefix(e, "SSH_TTY=") {
			finalEnv = append(finalEnv, e)
		}
	}
	for i, e := range finalEnv {
		if strings.HasPrefix(e, "PATH=") {
			finalEnv[i] = "PATH=" + tmpBin + string(os.PathListSeparator) + e[5:]
		}
	}
	cmd.Env = finalEnv
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &interceptorWriter{w: &stdout, buf: &bytes.Buffer{}}
	cmd.Stderr = &stderr

	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout.String(), stderr.String(), context.DeadlineExceeded
	}
	return stdout.String(), stderr.String(), err
}

func startMockLibp2pHub(t *testing.T) (peer.ID, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate hub key: %v", err)
	}

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create mock libp2p host: %v", err)
	}

	h.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		reader := msgio.NewVarintReaderSize(s, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		defer reader.ReleaseMsg(msg)

		writer := msgio.NewVarintWriter(s)
		resp := &api.AuthResponse{
			Success: true,
			Biscuit: createMockBiscuitToken(t, h.ID().String(), priv, api.RoleRouter),
		}
		respBytes, _ := proto.Marshal(resp)
		_ = writer.WriteMsg(respBytes)
	})

	kdht, err := dht.New(h, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatalf("failed to create DHT on mock hub: %v", err)
	}

	// Start HTTP server for enrollment

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		var req api.EnrollRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		resp := &api.EnrollResponse{
			BiscuitToken: createMockBiscuitToken(t, req.PeerId, priv, api.RoleNode),
			HubPublicKey: pub,
			HubAddresses: []string{h.Addrs()[0].String() + "/p2p/" + h.ID().String()},
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	httpServer := httptest.NewServer(mux)

	t.Cleanup(func() {
		httpServer.Close()
		_ = kdht.Close()
		_ = h.Close()
	})

	return h.ID(), httpServer.URL
}

func startMockLibp2pHubWithOIDC(t *testing.T, oidcIssuerURL string) (peer.ID, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate hub key: %v", err)
	}

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create mock libp2p host: %v", err)
	}

	h.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		reader := msgio.NewVarintReaderSize(s, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		defer reader.ReleaseMsg(msg)

		writer := msgio.NewVarintWriter(s)
		resp := &api.AuthResponse{
			Success: true,
			Biscuit: createMockBiscuitToken(t, h.ID().String(), priv, api.RoleRouter),
		}
		respBytes, _ := proto.Marshal(resp)
		_ = writer.WriteMsg(respBytes)
	})

	kdht, err := dht.New(h, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatalf("failed to create DHT on mock hub: %v", err)
	}

	// Start HTTP server for enrollment and info

	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp := &api.HubInfoResponse{
			OidcIssuer: oidcIssuerURL,
			ClientId:   "sam-mesh-audience",
			Audience:   "sam-mesh-audience",
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		var req api.EnrollRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		resp := &api.EnrollResponse{
			BiscuitToken: createMockBiscuitToken(t, req.PeerId, priv, api.RoleNode),
			HubPublicKey: pub,
			HubAddresses: []string{h.Addrs()[0].String() + "/p2p/" + h.ID().String()},
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	httpServer := httptest.NewServer(mux)

	t.Cleanup(func() {
		httpServer.Close()
		_ = kdht.Close()
		_ = h.Close()
	})

	return h.ID(), httpServer.URL
}

func createMockBiscuitToken(t *testing.T, peerID string, priv ed25519.PrivateKey, role string) []byte {
	builder := biscuit.NewBuilder(priv)
	err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: "target_unrestricted"}})
	if err != nil {
		t.Fatalf("failed to add target_unrestricted: %v", err)
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(1 * time.Hour))},
	}})
	if err != nil {
		t.Fatalf("failed to add FactExpiration fact: %v", err)
	}

	if role == "" {
		role = api.RoleRouter
	}
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactRole,
		IDs:  []biscuit.Term{biscuit.String(role)},
	}})
	if err != nil {
		t.Fatalf("failed to add role fact: %v", err)
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(peerID)},
	}})
	if err != nil {
		t.Fatalf("failed to add node fact: %v", err)
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(peerID)},
	}})
	if err != nil {
		t.Fatalf("failed to add client_peer_id fact: %v", err)
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "granted_service_all_types",
	}})
	if err != nil {
		t.Fatalf("failed to add granted_service_all_types fact: %v", err)
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build biscuit: %v", err)
	}
	serialized, err := b.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize biscuit: %v", err)
	}
	return serialized
}

func startControlPlaneAndRouter(t *testing.T, tmpDir string, oidcURL string, mintToken func(map[string]interface{}) string, policyFile string) (int, func()) {
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	routerBin := buildBinary(t, "./cmd/sam-router")

	cpPort := getFreePort(t)
	routerPort := getFreePort(t)

	// Automatically adjust the policy file to grant the "router" role to group "routers"
	originalPolicy, err := os.ReadFile(policyFile)
	if err == nil {
		writePolicyWithRouter(t, policyFile, string(originalPolicy))
	}

	// 1. Start Control Plane
	cpCmd := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", cpPort),
		"--db-dsn", filepath.Join(tmpDir, "cp-keys.db"),
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
		"--admin-token", "test-admin-token",
	)
	cpCmd.Stdout = os.Stdout
	cpCmd.Stderr = os.Stderr
	if err := cpCmd.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}

	// Wait for CP to be up
	waitForControlPlane(t, cpPort)

	// Inject policy into CP database via API
	injectPolicyYAML(t, cpPort, "test-admin-token", policyFile)

	// 2. Start Router
	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-integration-1",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	routerCmd := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPort),
		"--keys-path", filepath.Join(tmpDir, "router-keys.db"),
		"--allow-loopback",
		"--oidc-token", routerJWT,
	)
	routerCmd.Stdout = os.Stdout
	routerCmd.Stderr = os.Stderr
	if err := routerCmd.Start(); err != nil {
		_ = cpCmd.Process.Kill()
		_ = cpCmd.Wait()
		t.Fatalf("failed to start router: %v", err)
	}

	// Wait for router lease to be active and registered
	fetchPeerID(t, cpPort)

	cleanup := func() {
		_ = routerCmd.Process.Kill()
		_ = routerCmd.Wait()
		_ = cpCmd.Process.Kill()
		_ = cpCmd.Wait()
	}

	return cpPort, cleanup
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func fetchPeerID(t *testing.T, port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		var peerID string
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/info", port))
		if err == nil {
			bodyBytes, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil {
				var info api.HubInfoResponse
				if err := proto.Unmarshal(bodyBytes, &info); err == nil {
					if len(info.HubAddresses) > 0 {
						peerID = extractPeerID(info.HubAddresses[0])
					}
				}
			}
		}

		if peerID != "" {
			return peerID
		}

		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for router lease registration on /info: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func extractPeerID(maddrStr string) string {
	parts := strings.Split(maddrStr, "/")
	for i, part := range parts {
		if part == "p2p" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func waitForDHTReady(t *testing.T, clientBin string, apiPort int, token string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	cmdArgs := []string{
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp", apiPort),
		"-token", token,
		"-tool", "get_mesh_info",
		"-args", `{}`,
	}

	for time.Now().Before(deadline) {
		cmd := exec.Command(clientBin, cmdArgs...)
		out, err := cmd.Output()
		if err == nil {
			if strings.Contains(string(out), `"dht_size":`) && !strings.Contains(string(out), `"dht_size":0`) {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("DHT not ready on port %d", apiPort)
}

func waitForControlPlane(t *testing.T, port int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/info", port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}

		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for control plane: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func writePolicyWithRouter(t *testing.T, path string, yamlContent string) {
	t.Helper()
	content := yamlContent

	// Replace empty markers first
	content = strings.ReplaceAll(content, "bindings: []", "bindings:")
	content = strings.ReplaceAll(content, "roles: {}", "roles:")

	routerRole := fmt.Sprintf(`  %s:
    allowed_services: []
    allowed_targets: ["*"]`, api.RoleRouter)
	routerBinding := fmt.Sprintf(`  - role: %s
    members: ["group:routers"]`, api.RoleRouter)

	if strings.Contains(content, "roles:") {
		content = strings.Replace(content, "roles:", "roles:\n"+routerRole, 1)
	} else {
		content += "\nroles:\n" + routerRole
	}

	if strings.Contains(content, "bindings:") {
		content = strings.Replace(content, "bindings:", "bindings:\n"+routerBinding, 1)
	} else {
		content += "\nbindings:\n" + routerBinding
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func waitForNodeOnline(t *testing.T, logPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		data, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(data), "SAM Node Online") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for node to go online")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type testBinding struct {
	Role    string   `yaml:"role"`
	Members []string `yaml:"members"`
}

type testRolePolicy struct {
	AllowedTargets  []string `yaml:"allowed_targets"`
	AllowedServices []string `yaml:"allowed_services"`
}

type testPolicyConfig struct {
	Bindings []testBinding             `yaml:"bindings"`
	Roles    map[string]testRolePolicy `yaml:"roles"`
}

func injectPolicyYAML(t *testing.T, port int, adminToken string, policyFile string) {
	t.Helper()

	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("failed to read policy file %s: %v", policyFile, err)
	}

	var config testPolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("failed to unmarshal policy file %s: %v", policyFile, err)
	}

	reqData := &api.PolicyConfigUpdateRequest{
		Roles:    make([]*api.PolicyRole, 0, len(config.Roles)),
		Bindings: make([]*api.PolicyBinding, 0, len(config.Bindings)),
	}

	for name, role := range config.Roles {
		reqData.Roles = append(reqData.Roles, &api.PolicyRole{
			Name:            name,
			AllowedServices: role.AllowedServices,
			AllowedTargets:  role.AllowedTargets,
		})
	}
	for _, b := range config.Bindings {
		reqData.Bindings = append(reqData.Bindings, &api.PolicyBinding{
			Role:    b.Role,
			Members: b.Members,
		})
	}

	protoData, err := proto.Marshal(reqData)
	if err != nil {
		t.Fatalf("failed to marshal policy request: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/policies", port), bytes.NewReader(protoData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to POST policy to control plane: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected POST /policies status: %s (body: %s)", resp.Status, string(body))
	}
}
