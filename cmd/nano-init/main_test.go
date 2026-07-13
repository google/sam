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
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBootstrapCA(t *testing.T) {
	tempDir := t.TempDir()
	udsPath := filepath.Join(tempDir, "mock-sam-box.sock")

	// Start a mock HTTP server on a Unix Domain Socket
	listener, err := net.Listen("unix", udsPath)
	if err != nil {
		t.Fatalf("Failed to listen on UDS: %v", err)
	}
	defer func() { _ = listener.Close() }()

	mockCACert := []byte("fake-ca-cert-data")

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && r.URL.Path == "/internal/bootstrap/ca.crt" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(mockCACert)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	}
	go func() {
		_ = srv.Serve(listener)
	}()
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Clean target file if it already exists
	_ = os.Remove("/tmp/ephemeral_ca.pem")
	defer func() { _ = os.Remove("/tmp/ephemeral_ca.pem") }()

	if err := bootstrapCA(ctx, udsPath); err != nil {
		t.Fatalf("bootstrapCA failed: %v", err)
	}

	data, err := os.ReadFile("/tmp/ephemeral_ca.pem")
	if err != nil {
		t.Fatalf("Failed to read bootstrap CA: %v", err)
	}

	if string(data) != string(mockCACert) {
		t.Errorf("Expected cert data %q, got %q", string(mockCACert), string(data))
	}
}

func TestDNSSpoofer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dnsAddr := "127.0.0.1:10053"
	if err := startDNSSpoofer(ctx, dnsAddr); err != nil {
		t.Fatalf("Failed to start DNS spoofer: %v", err)
	}

	// Create UDP connection to make queries
	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to dial DNS spoofer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Query A record
	msgA := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               1234,
			OpCode:           0,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("api.github.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packedA, _ := msgA.Pack()
	_, _ = conn.Write(packedA)

	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read DNS reply: %v", err)
	}

	var respA dnsmessage.Message
	if err := respA.Unpack(buf[:n]); err != nil {
		t.Fatalf("Failed to unpack DNS response: %v", err)
	}

	if len(respA.Answers) == 0 {
		t.Fatalf("No answers in DNS A response")
	}

	answerA := respA.Answers[0]
	if answerA.Header.Type != dnsmessage.TypeA {
		t.Fatalf("Expected A record answer, got %v", answerA.Header.Type)
	}

	bodyVarA := answerA.Body
	aRes, ok := bodyVarA.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("Expected AResource body type")
	}

	expectedA := [4]byte{127, 0, 0, 1}
	if aRes.A != expectedA {
		t.Errorf("Expected A record %v, got %v", expectedA, aRes.A)
	}

	// Query AAAA record
	msgAAAA := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               5678,
			OpCode:           0,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("api.github.com."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packedAAAA, _ := msgAAAA.Pack()
	_, _ = conn.Write(packedAAAA)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read DNS reply: %v", err)
	}

	var respAAAA dnsmessage.Message
	if err := respAAAA.Unpack(buf[:n]); err != nil {
		t.Fatalf("Failed to unpack DNS response: %v", err)
	}

	if len(respAAAA.Answers) == 0 {
		t.Fatalf("No answers in DNS AAAA response")
	}

	answerAAAA := respAAAA.Answers[0]
	if answerAAAA.Header.Type != dnsmessage.TypeAAAA {
		t.Fatalf("Expected AAAA record answer, got %v", answerAAAA.Header.Type)
	}

	bodyVarAAAA := answerAAAA.Body
	aaaaRes, ok := bodyVarAAAA.(*dnsmessage.AAAAResource)
	if !ok {
		t.Fatalf("Expected AAAAResource body type")
	}

	expectedAAAA := net.ParseIP("::1").To16()
	var expectedAAAABytes [16]byte
	copy(expectedAAAABytes[:], expectedAAAA)

	if aaaaRes.AAAA != expectedAAAABytes {
		t.Errorf("Expected AAAA record %v, got %v", expectedAAAABytes, aaaaRes.AAAA)
	}
}

func TestTCPForwarder(t *testing.T) {
	tempDir := t.TempDir()
	udsPath := filepath.Join(tempDir, "mock-uds.sock")

	// UDS Listener (representing gateway)
	udsListener, err := net.Listen("unix", udsPath)
	if err != nil {
		t.Fatalf("Failed to listen on UDS: %v", err)
	}
	defer func() { _ = udsListener.Close() }()

	mockGatewayMsg := []byte("hello from gateway")

	go func() {
		conn, err := udsListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write(mockGatewayMsg)
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn, udsPath)
		}
	}()

	// Dial forwarder
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial forwarder: %v", err)
	}
	defer func() { _ = conn.Close() }()

	reply := make([]byte, len(mockGatewayMsg))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("Failed to read from forwarder connection: %v", err)
	}

	if string(reply) != string(mockGatewayMsg) {
		t.Errorf("Expected message %q, got %q", string(mockGatewayMsg), string(reply))
	}
}

func TestBuildAgentEnv(t *testing.T) {
	caPath := "/tmp/test_ca.pem"
	interceptorPath := "/tmp/test_interceptor.so"

	env := buildAgentEnv(1234, caPath, interceptorPath)

	expected := map[string]string{
		"SSL_CERT_FILE":       caPath,
		"REQUESTS_CA_BUNDLE":  caPath,
		"NODE_EXTRA_CA_CERTS": caPath,
		"HTTP_PROXY":          "http://127.0.0.1:1234",
		"HTTPS_PROXY":         "http://127.0.0.1:1234",
		"ALL_PROXY":           "http://127.0.0.1:1234",
		"http_proxy":          "http://127.0.0.1:1234",
		"https_proxy":         "http://127.0.0.1:1234",
		"all_proxy":           "http://127.0.0.1:1234",
		"SAM_PROXY_PORT":      "1234",
		"LD_PRELOAD":          interceptorPath,
	}

	envMap := make(map[string]string)
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	for k, expectedVal := range expected {
		val, exists := envMap[k]
		if !exists {
			t.Errorf("Expected environment variable %s to be set", k)
			continue
		}
		if val != expectedVal {
			t.Errorf("Expected environment variable %s to be %q, got %q", k, expectedVal, val)
		}
	}
}

func TestCopyFile(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "source-file")
	dest := filepath.Join(tempDir, "dest-file")

	content := []byte("hello copy world")
	if err := os.WriteFile(src, content, 0755); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	if err := copyFile(src, dest); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("Failed to read dest file: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("Expected content %q, got %q", string(content), string(data))
	}

	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("Stat dest failed: %v", err)
	}

	expectedMode := os.FileMode(0755)
	if fi.Mode().Perm() != expectedMode {
		t.Errorf("Expected permissions %v, got %v", expectedMode, fi.Mode().Perm())
	}
}

func TestBootstrapInterceptor(t *testing.T) {
	tempDir := t.TempDir()
	udsPath := filepath.Join(tempDir, "mock-sam-box-interceptor.sock")

	listener, err := net.Listen("unix", udsPath)
	if err != nil {
		t.Fatalf("Failed to listen on UDS: %v", err)
	}
	defer func() { _ = listener.Close() }()

	mockSO := []byte("fake-shared-library-so-data")
	var receivedArch, receivedLibc string

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && r.URL.Path == "/internal/bootstrap/libinterceptor.so" {
				receivedArch = r.URL.Query().Get("arch")
				receivedLibc = r.URL.Query().Get("libc")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(mockSO)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	}
	go func() {
		_ = srv.Serve(listener)
	}()
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = os.Remove("/tmp/libinterceptor.so")
	defer func() { _ = os.Remove("/tmp/libinterceptor.so") }()

	soPath, err := bootstrapInterceptor(ctx, udsPath)
	if err != nil {
		t.Fatalf("bootstrapInterceptor failed: %v", err)
	}

	if soPath != "/tmp/libinterceptor.so" {
		t.Errorf("Expected path '/tmp/libinterceptor.so', got %q", soPath)
	}

	data, err := os.ReadFile("/tmp/libinterceptor.so")
	if err != nil {
		t.Fatalf("Failed to read bootstrap SO: %v", err)
	}

	if string(data) != string(mockSO) {
		t.Errorf("Expected SO data %q, got %q", string(mockSO), string(data))
	}

	if receivedArch == "" {
		t.Errorf("Expected arch query parameter to be passed, but was empty")
	}
	if receivedLibc == "" {
		t.Errorf("Expected libc query parameter to be passed, but was empty")
	}

	// Test fallback / error case (server returns 404)
	errSrvListener, err := net.Listen("unix", filepath.Join(tempDir, "mock-error-sam-box.sock"))
	if err == nil {
		defer func() { _ = errSrvListener.Close() }()
		errSrv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}),
		}
		go func() { _ = errSrv.Serve(errSrvListener) }()
		defer func() { _ = errSrv.Close() }()

		_, err = bootstrapInterceptor(ctx, errSrvListener.Addr().String())
		if err == nil {
			t.Errorf("Expected bootstrapInterceptor to return error when server returns 404")
		}
	}
}
