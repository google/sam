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
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type SecretKind string

const (
	SecretKindBearer       SecretKind = "Bearer"
	SecretKindCustomHeader SecretKind = "CustomHeader"
	SecretKindBasicAuth    SecretKind = "BasicAuth"
)

type SecretConfig struct {
	Kind       SecretKind `yaml:"kind" json:"kind"`
	HeaderName string     `yaml:"header_name" json:"header_name"`
	Value      string     `yaml:"value" json:"value"`
}

type CA struct {
	CertBytes   []byte
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func GenerateEphemeralCA() (*CA, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ephemeral SamBox CA"},
			CommonName:   "SamBox Ephemeral Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &CA{
		CertBytes:   certPEM,
		Certificate: cert,
		PrivateKey:  priv,
	}, nil
}

type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

func NewCertCache() *CertCache {
	return &CertCache{
		certs: make(map[string]*tls.Certificate),
	}
}

func (c *CertCache) GetCertificate(sni string, ca *CA) (*tls.Certificate, error) {
	c.mu.RLock()
	cert, exists := c.certs[sni]
	c.mu.RUnlock()
	if exists {
		return cert, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, exists = c.certs[sni]; exists {
		return cert, nil
	}

	newCert, err := GenerateLeafCert(sni, ca)
	if err != nil {
		return nil, err
	}
	c.certs[sni] = newCert
	return newCert, nil
}

func GenerateLeafCert(sni string, ca *CA) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
		},
		DNSNames:  []string{sni},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &priv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privDer := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDer,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

type Gateway struct {
	CA              *CA
	CertCache       *CertCache
	SecretStore     map[string]SecretConfig
	Transport       http.RoundTripper
	InterceptorsDir string
}

func NewGateway(secretStore map[string]SecretConfig, transport http.RoundTripper, interceptorsDir string) (*Gateway, error) {
	ca, err := GenerateEphemeralCA()
	if err != nil {
		return nil, err
	}
	return &Gateway{
		CA:              ca,
		CertCache:       NewCertCache(),
		SecretStore:     secretStore,
		Transport:       transport,
		InterceptorsDir: interceptorsDir,
	}, nil
}

func (g *Gateway) Serve(listener net.Listener) error {
	tlsListener := &channelListener{
		conns:  make(chan net.Conn, 100),
		closed: make(chan struct{}),
	}
	defer func() { _ = tlsListener.Close() }()

	director := func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		req.Header.Set("Authorization", "Bearer mock-token")
	}

	proxy := &httputil.ReverseProxy{
		Director:  director,
		Transport: g.Transport,
	}

	server := &http.Server{
		Handler: proxy,
	}

	serverErrChan := make(chan error, 1)
	go func() {
		if err := server.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			select {
			case <-tlsListener.closed:
				return nil
			default:
				return err
			}
		}

		go g.handleConnection(rawConn, tlsListener)
	}
}

func (g *Gateway) handleConnection(rawConn net.Conn, tlsListener *channelListener) {
	br := bufio.NewReader(rawConn)
	peekBytes, err := br.Peek(5)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	conn := &bufferedConn{
		Conn: rawConn,
		r:    br,
	}

	if len(peekBytes) > 0 && peekBytes[0] == 0x16 {
		tlsConfig := &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni := info.ServerName
				if sni == "" {
					return nil, fmt.Errorf("missing SNI")
				}
				return g.CertCache.GetCertificate(sni, g.CA)
			},
		}
		tlsConn := tls.Server(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			_ = tlsConn.Close()
			return
		}

		select {
		case tlsListener.conns <- tlsConn:
		case <-tlsListener.closed:
			_ = tlsConn.Close()
		}
	} else {
		g.handleHTTPConnection(conn, tlsListener)
	}
}

func (g *Gateway) handleHTTPConnection(conn net.Conn, tlsListener *channelListener) {
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		_ = conn.Close()
		return
	}

	if req.Method == "CONNECT" {
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			_ = conn.Close()
			return
		}
		g.upgradeToTLS(conn, req.Host, tlsListener)
		return
	}

	defer func() { _ = conn.Close() }()

	if req.Method == "GET" && req.URL.Path == "/internal/bootstrap/ca.crt" {
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len(g.CA.CertBytes)),
			Body:          io.NopCloser(bytes.NewReader(g.CA.CertBytes)),
			Header:        make(http.Header),
		}
		resp.Header.Set("Content-Type", "application/x-x509-ca-cert")
		_ = resp.Write(conn)
	} else if req.Method == "GET" && req.URL.Path == "/internal/bootstrap/libinterceptor.so" {
		if g.InterceptorsDir == "" {
			write404(conn)
			return
		}
		arch := req.URL.Query().Get("arch")
		libc := req.URL.Query().Get("libc")

		var filename string
		if arch != "" && libc != "" {
			filename = fmt.Sprintf("libinterceptor-%s-%s.so", arch, libc)
		} else {
			filename = "libinterceptor.so"
		}

		filePath := filepath.Join(g.InterceptorsDir, filename)
		fileData, err := os.ReadFile(filePath)
		if err != nil && filename != "libinterceptor.so" {
			filePath = filepath.Join(g.InterceptorsDir, "libinterceptor.so")
			fileData, err = os.ReadFile(filePath)
		}

		if err != nil {
			write404(conn)
			return
		}

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len(fileData)),
			Body:          io.NopCloser(bytes.NewReader(fileData)),
			Header:        make(http.Header),
		}
		resp.Header.Set("Content-Type", "application/octet-stream")
		_ = resp.Write(conn)
	} else {
		write404(conn)
	}
}

func write404(conn net.Conn) {
	resp := &http.Response{
		StatusCode: http.StatusNotFound,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
		Header:     make(http.Header),
	}
	_ = resp.Write(conn)
}

func (g *Gateway) upgradeToTLS(rawConn net.Conn, sni string, tlsListener *channelListener) {
	host, _, err := net.SplitHostPort(sni)
	if err != nil {
		host = sni
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return g.CertCache.GetCertificate(host, g.CA)
		},
	}

	tlsConn := tls.Server(rawConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}

	select {
	case tlsListener.conns <- tlsConn:
	case <-tlsListener.closed:
		_ = tlsConn.Close()
	}
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

type channelListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, io.EOF
	}
}

func (l *channelListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *channelListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "internal-tls-multiplexer", Net: "unix"}
}
