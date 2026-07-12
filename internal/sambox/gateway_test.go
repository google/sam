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
	gateway, err := NewGateway(nil, transport, "")
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
