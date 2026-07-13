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

package sambox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateEphemeralCA(t *testing.T) {
	ca, err := GenerateEphemeralCA()
	if err != nil {
		t.Fatalf("GenerateEphemeralCA failed: %v", err)
	}

	if len(ca.CertBytes) == 0 {
		t.Fatal("Empty CertBytes")
	}

	if ca.Certificate == nil {
		t.Fatal("Certificate is nil")
	}

	if ca.PrivateKey == nil {
		t.Fatal("PrivateKey is nil")
	}

	// Validate self-signed
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := ca.Certificate.Verify(opts); err != nil {
		t.Fatalf("Certificate self-verification failed: %v", err)
	}
}

func TestCertCache(t *testing.T) {
	ca, _ := GenerateEphemeralCA()
	cache := NewCertCache()

	cert1, err := cache.GetCertificate("example.com", ca)
	if err != nil {
		t.Fatalf("Failed to get cert: %v", err)
	}

	cert2, err := cache.GetCertificate("example.com", ca)
	if err != nil {
		t.Fatalf("Failed to get cert second time: %v", err)
	}

	if cert1 != cert2 {
		t.Errorf("CertCache did not cache the certificate")
	}

	cert3, err := cache.GetCertificate("another.com", ca)
	if err != nil {
		t.Fatalf("Failed to get cert for different domain: %v", err)
	}

	if cert1 == cert3 {
		t.Errorf("CertCache returned same certificate for different domains")
	}
}

func TestGatewayPlaintextAndTerminatingProxy(t *testing.T) {
	// 1. Upstream Mock Server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer mock-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("mock upstream response"))
	}))
	defer upstream.Close()

	// Redirect proxy calls to upstream mock server
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, upstream.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// 2. Gateway setup
	secretStore := map[string]SecretConfig{
		"example.com": {
			Kind:  SecretKindBearer,
			Value: "mock-token",
		},
	}
	gateway, err := NewGateway(secretStore, transport, "")
	if err != nil {
		t.Fatalf("NewGateway failed: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		_ = gateway.Serve(listener)
	}()

	addr := listener.Addr().String()

	// 3. Test Plaintext HTTP bootstrap download
	resp, err := http.Get("http://" + addr + "/internal/bootstrap/ca.crt")
	if err != nil {
		t.Fatalf("Failed to download CA cert: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	certBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read CA cert response body: %v", err)
	}

	// Verify that a second download attempt is blocked (one-shot protection)
	respSecond, err := http.Get("http://" + addr + "/internal/bootstrap/ca.crt")
	if err != nil {
		t.Fatalf("Second download request failed: %v", err)
	}
	defer func() { _ = respSecond.Body.Close() }()
	if respSecond.StatusCode != http.StatusForbidden {
		t.Errorf("Expected second download to be forbidden (403), got status: %d", respSecond.StatusCode)
	}

	// Verify downloaded cert matches gateway cert
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certBytes) {
		t.Fatalf("Failed to parse downloaded certificate as PEM")
	}

	// 4. Test TLS Terminating Proxy
	tlsConfig := &tls.Config{
		RootCAs: roots,
	}

	// Create custom client that dials the gateway but expects "example.com" domain
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}

	resp2, err := client.Get("https://example.com/some-path")
	if err != nil {
		t.Fatalf("Terminating TLS proxy request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 from upstream, got %d", resp2.StatusCode)
	}

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body2) != "mock upstream response" {
		t.Errorf("Expected 'mock upstream response', got %q", string(body2))
	}
}

func TestGatewayOneShotAndSanitization(t *testing.T) {
	// Create a temporary directory containing mock interceptor files
	tempInterceptorsDir := t.TempDir()
	mockLibData := []byte("mock-so-binary-content")
	if err := os.WriteFile(filepath.Join(tempInterceptorsDir, "libinterceptor-amd64-glibc.so"), mockLibData, 0644); err != nil {
		t.Fatalf("Failed to create mock interceptor file: %v", err)
	}

	gateway, err := NewGateway(nil, nil, tempInterceptorsDir)
	if err != nil {
		t.Fatalf("NewGateway failed: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		_ = gateway.Serve(listener)
	}()

	addr := listener.Addr().String()
	client := &http.Client{Timeout: 2 * time.Second}

	// 1. First download of ca.crt should succeed
	resp1, err := client.Get("http://" + addr + "/internal/bootstrap/ca.crt")
	if err != nil {
		t.Fatalf("First ca.crt request failed: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for first ca.crt request, got %d", resp1.StatusCode)
	}

	// 2. Second download of ca.crt should be forbidden (one-shot)
	resp2, err := client.Get("http://" + addr + "/internal/bootstrap/ca.crt")
	if err != nil {
		t.Fatalf("Second ca.crt request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for second ca.crt request, got %d", resp2.StatusCode)
	}

	// 3. First download of valid interceptor should succeed
	resp3, err := client.Get("http://" + addr + "/internal/bootstrap/libinterceptor.so?arch=amd64&libc=glibc")
	if err != nil {
		t.Fatalf("First interceptor request failed: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for first interceptor request, got %d", resp3.StatusCode)
	}

	// 4. Second download of interceptor should be forbidden (one-shot)
	resp4, err := client.Get("http://" + addr + "/internal/bootstrap/libinterceptor.so?arch=amd64&libc=glibc")
	if err != nil {
		t.Fatalf("Second interceptor request failed: %v", err)
	}
	_ = resp4.Body.Close()
	if resp4.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for second interceptor request, got %d", resp4.StatusCode)
	}

	// 5. Test path traversal and input sanitization (using a fresh Gateway to bypass the one-shot check for interceptor)
	gateway2, _ := NewGateway(nil, nil, tempInterceptorsDir)
	listener5, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = listener5.Close() }()
	go func() { _ = gateway2.Serve(listener5) }()
	addr2 := listener5.Addr().String()

	traversalURLs := []string{
		"http://" + addr2 + "/internal/bootstrap/libinterceptor.so?arch=../&libc=glibc",
		"http://" + addr2 + "/internal/bootstrap/libinterceptor.so?arch=amd64&libc=..\\",
		"http://" + addr2 + "/internal/bootstrap/libinterceptor.so?arch=amd64.so&libc=glibc",
		"http://" + addr2 + "/internal/bootstrap/libinterceptor.so?arch=amd64&libc=glibc;invalid",
	}

	for _, u := range traversalURLs {
		resp, err := client.Get(u)
		if err != nil {
			t.Fatalf("Request to %q failed: %v", u, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 for invalid identifier URL %q, got %d", u, resp.StatusCode)
		}
	}
}
