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

package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/sam/api"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/encoding/protojson"
)

// StartSidecarServer serves the node's local API on a TCP address, on a Unix
// socket, or on both. An empty addr disables the TCP listener; an empty
// socketPath disables the socket.
func StartSidecarServer(node *SamNode, addr, socketPath, token, certFile, keyFile, caFile string) (*http.Server, error) {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)
	mux.Handle("/metrics", promhttp.Handler())

	// Protected endpoints. allowAuthorizationFallback=true is safe here: none of
	// these ever forward the inbound Authorization header to another service.
	mux.Handle("/sam/service/register", withAuth(token, true, withMeshConnection(node, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRegisterService(node, w, r)
	}))))
	mux.Handle("/sam/service/unregister", withAuth(token, true, withMeshConnection(node, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleUnregisterService(node, w, r)
	}))))
	mux.Handle("/sam/service/discover", withAuth(token, true, withMeshConnection(node, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDiscoverService(node, w, r)
	}))))

	// Mount Egress Proxy. allowAuthorizationFallback=false is required here: this
	// handler forwards Authorization to the destination service, so it must never
	// also accept it as the local gate credential (would leak the sidecar token off-node).
	egress := createEgressProxy(node)
	mux.Handle("/sam/", withAuth(token, false, withMeshConnection(node, egress)))

	// OpenAI-compatible facade: point any OpenAI SDK at the sidecar.
	// allowAuthorizationFallback=true lets SDKs send the sidecar token as their
	// api_key; withAuth strips whichever header carried it, so an Authorization
	// header that survives the gate is the backend's own credential and is
	// forwarded like on the egress path.
	facade := newOpenAIFacade(node, egress)
	mux.Handle("/v1/models", withAuth(token, true, withMeshConnection(node, http.HandlerFunc(facade.handleModels))))
	mux.Handle("/v1/chat/completions", withAuth(token, true, withMeshConnection(node, http.HandlerFunc(facade.handleCompletions))))
	mux.Handle("/v1/completions", withAuth(token, true, withMeshConnection(node, http.HandlerFunc(facade.handleCompletions))))

	// Mount MCP handler
	mcpHandler := NewMCPHandler(node)
	mux.Handle("/", withAuth(token, true, withMeshConnection(node, mcpHandler)))

	server := &http.Server{
		Handler: observeRequests(mux),
		// Bound header-read time only: bodies/responses can legitimately stream
		// (MCP sessions, inference completions), so no ReadTimeout/WriteTimeout.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnContext:       markLocalSocketConn,
	}

	if addr == "" && socketPath == "" {
		return nil, fmt.Errorf("no local API listener configured: set --bind-addr, --socket-path, or both")
	}
	if (certFile != "") != (keyFile != "") {
		return nil, fmt.Errorf("both --tls-cert and --tls-key must be provided to enable TLS")
	}

	var socketListener net.Listener
	if socketPath != "" {
		l, err := bindLocalSocket(socketPath, addr == "")
		if err != nil {
			return nil, err
		}
		if l != nil {
			socketListener = l
			node.BoundSocketPath = socketPath
		}
	}

	if addr != "" {
		if err := serveTCP(server, node, addr, token, certFile, keyFile, caFile); err != nil {
			if socketListener != nil {
				_ = socketListener.Close()
			}
			return nil, err
		}
	}

	serveSocket(server, socketListener, socketPath)

	return server, nil
}

// bindLocalSocket binds the local API socket. Unless it is the only way into
// the node, a path the OS rejects only downgrades to a warning: the socket is a
// convenience on top of a working TCP listener and must never keep the node
// from starting. A nil listener with a nil error means exactly that.
func bindLocalSocket(socketPath string, required bool) (net.Listener, error) {
	listener, err := listenLocalSocket(socketPath)
	if err == nil {
		return listener, nil
	}
	if required {
		return nil, err
	}
	logger.Warnf("Local API socket disabled: %v", err)
	return nil, nil
}

func serveSocket(server *http.Server, listener net.Listener, socketPath string) {
	if listener == nil {
		return
	}
	logger.Infof("Serving the local API on Unix socket %s", socketPath)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Errorf("Sidecar API socket server error: %v", err)
		}
	}()
}

// serveTCP starts the sidecar's TCP listener, which — unlike the Unix socket —
// is reachable by any local process and therefore always demands a token or
// mutual TLS.
func serveTCP(server *http.Server, node *SamNode, addr, token, certFile, keyFile, caFile string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	actualAddr := listener.Addr().String()
	node.BoundHTTPAddr = actualAddr

	if certFile != "" && keyFile != "" {
		tlsConfig := &tls.Config{}
		isMTLS := false
		if caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				_ = listener.Close()
				return fmt.Errorf("failed to read CA cert: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			isMTLS = true
		}

		if !isMTLS && token == "" {
			_ = listener.Close()
			return fmt.Errorf("token is mandatory when not using mTLS")
		}

		server.TLSConfig = tlsConfig
		logger.Infof("Starting MCP server on TCP address %s (with TLS Sidecar)", actualAddr)
		go func() {
			if err := server.ServeTLS(listener, certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Errorf("Sidecar API server error: %v", err)
			}
		}()
		return nil
	}

	if token == "" {
		_ = listener.Close()
		return fmt.Errorf("token is mandatory when not using mTLS")
	}
	logger.Infof("Starting MCP server on TCP address %s", actualAddr)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Errorf("Sidecar API server error: %v", err)
		}
	}()
	return nil
}

// listenLocalSocket binds the local API to a Unix socket whose permissions are
// the credential: only the user who owns it can reach the mesh through it. A
// socket left behind by a crashed node is replaced, one a live node is still
// answering on is not.
func listenLocalSocket(path string) (net.Listener, error) {
	// The kernel's sun_path is a fixed-size buffer, and overflowing it only
	// yields "invalid argument" from bind(2).
	if len(path) >= 104 {
		return nil, fmt.Errorf("socket path %q is too long (%d bytes, the kernel allows 103)", path, len(path))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating the socket directory: %w", err)
	}

	if info, err := os.Stat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s already exists and is not a socket", path)
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("another node is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing the stale socket %s: %w", path, err)
		}
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restricting access to %s: %w", path, err)
	}
	return listener, nil
}

type localSocketContextKey struct{}

// markLocalSocketConn tags connections accepted on the Unix socket so the auth
// gate can tell them apart from anything arriving over TCP.
func markLocalSocketConn(ctx context.Context, c net.Conn) context.Context {
	if addr := c.LocalAddr(); addr != nil && addr.Network() == "unix" {
		return context.WithValue(ctx, localSocketContextKey{}, true)
	}
	return ctx
}

// fromLocalSocket reports whether the request arrived over the node's Unix socket.
func fromLocalSocket(r *http.Request) bool {
	authorized, _ := r.Context().Value(localSocketContextKey{}).(bool)
	return authorized
}

// StartUnauthSidecarServer serves the enrollment-only API of a node that has no
// identity yet, on a TCP address, on a Unix socket, or on both.
func StartUnauthSidecarServer(controlPlaneURL, addr, socketPath, certFile, keyFile string) (*http.Server, error) {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)

	// Mount Unauthenticated MCP handler
	mcpHandler := NewUnauthenticatedMCPHandler(controlPlaneURL)
	mux.Handle("/", mcpHandler)

	server := &http.Server{
		Handler: mux,
		// Bound header-read time only: MCP sessions can legitimately stream.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if addr == "" && socketPath == "" {
		return nil, fmt.Errorf("no local API listener configured: set --bind-addr, --socket-path, or both")
	}
	if (certFile != "") != (keyFile != "") {
		return nil, fmt.Errorf("both --tls-cert and --tls-key must be provided to enable TLS")
	}

	var socketListener net.Listener
	if socketPath != "" {
		l, err := bindLocalSocket(socketPath, addr == "")
		if err != nil {
			return nil, err
		}
		socketListener = l
	}

	if addr != "" {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			if socketListener != nil {
				_ = socketListener.Close()
			}
			return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
		}

		actualAddr := listener.Addr().String()
		if certFile != "" && keyFile != "" {
			logger.Infof("Starting Unauthenticated MCP server on TCP address %s (with TLS Sidecar)", actualAddr)
			go func() {
				if err := server.ServeTLS(listener, certFile, keyFile); err != nil && err != http.ErrServerClosed {
					logger.Errorf("Unauth Sidecar API server error: %v", err)
				}
			}()
		} else {
			logger.Infof("Starting Unauthenticated MCP server on TCP address %s", actualAddr)
			go func() {
				if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
					logger.Errorf("Unauth Sidecar API server error: %v", err)
				}
			}()
		}
	}

	serveSocket(server, socketListener, socketPath)

	return server, nil
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		logger.Errorf("Failed to write response: %v", err)
	}
}

func handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		logger.Errorf("Failed to write response: %v", err)
	}
}

func withMeshConnection(node *SamNode, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if node != nil && !node.IsConnected() {
			logger.Warnf("[SidecarAuth] Request %s %s rejected: node not connected to mesh", r.Method, r.URL.Path)
			http.Error(w, "Service Unavailable: Not connected to the mesh", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withAuth gates a handler behind the sidecar's shared-secret token.
//
// allowAuthorizationFallback additionally accepts the standard "Authorization"
// header as the local gate credential, for endpoints that never forward it to
// another service. It must be false for anything that proxies the request
// onward (the egress/inference proxy), since there "Authorization" is reserved
// exclusively for the destination's own credential and must never double as
// (or leak) the local sidecar token.
func withAuth(token string, allowAuthorizationFallback bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("[SidecarAuth] Incoming request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		if fromLocalSocket(r) {
			// Reaching the socket at all already proves the caller is the user
			// who owns it, which is the same bar as reading the token file.
			r.Header.Del(api.HeaderSamAuthentication)
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			// If token is empty, we assume mTLS is handling authentication.
			// StartSidecarServer enforces that token is present if mTLS is not used.
			next.ServeHTTP(w, r)
			return
		}

		headerName := api.HeaderSamAuthentication
		authHeader := r.Header.Get(headerName)
		if authHeader == "" && allowAuthorizationFallback {
			headerName = "Authorization"
			authHeader = r.Header.Get(headerName)
		}
		if authHeader == "" {
			accepted := fmt.Sprintf("%q", api.HeaderSamAuthentication)
			if allowAuthorizationFallback {
				accepted += ` or "Authorization"`
			}
			logger.Warnf("[SidecarAuth] Request %s %s rejected: missing %s header", r.Method, r.URL.Path, accepted)
			http.Error(w, fmt.Sprintf("Unauthorized: missing %s header, e.g. %q: \"Bearer <api-token>\"", accepted, api.HeaderSamAuthentication), http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, fmt.Sprintf("Invalid %q header format, expected \"Bearer <api-token>\"", headerName), http.StatusUnauthorized)
			return
		}

		if parts[1] != token {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// The gate credential is local-only: strip exactly the header it came in
		// on so it can never flow past the gate. Anything left (e.g. Authorization
		// when the gate was passed via X-Sam-Authentication) is the destination
		// service's own credential and passes through untouched.
		r.Header.Del(headerName)

		next.ServeHTTP(w, r)
	})
}

type ServiceRequest struct {
	ServiceName string `json:"service_name"`
}

// maxRequestBodyBytes caps request bodies read into memory to guard
// against memory-exhaustion from oversized payloads.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

func handleRegisterService(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	_ = r.Body.Close()

	var req api.RegisterServiceRequest
	if err := protojson.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.Service == nil {
		http.Error(w, "service field is required", http.StatusBadRequest)
		return
	}

	if req.Service.Name == "" || req.Service.Type == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		http.Error(w, "name and type are required", http.StatusBadRequest)
		return
	}

	if req.Backend == nil {
		http.Error(w, "backend is required", http.StatusBadRequest)
		return
	}

	if err := node.RegisterService(r.Context(), &req); err != nil {
		logger.Errorf("Failed to register service: %v", err)
		http.Error(w, fmt.Sprintf("Failed to register service: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service registered")); err != nil {
		logger.Errorf("Failed to write response: %v", err)
	}
}

func handleUnregisterService(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req api.ServiceInfo
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := node.UnregisterService(r.Context(), req.Name); err != nil {
		http.Error(w, fmt.Sprintf("Failed to unregister service: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Service unregistered")); err != nil {
		logger.Errorf("Failed to write response: %v", err)
	}
}

func handleDiscoverService(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serviceName := r.URL.Query().Get("name")
	serviceTypeStr := r.URL.Query().Get("type")
	if serviceTypeStr == "" {
		http.Error(w, "type query parameter is required", http.StatusBadRequest)
		return
	}

	serviceType, err := api.ParseServiceType(serviceTypeStr)
	if err != nil || serviceType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		http.Error(w, "Invalid or unspecified service type", http.StatusBadRequest)
		return
	}

	timeoutStr := r.URL.Query().Get("timeout")
	var customTimeout time.Duration
	if timeoutStr != "" {
		customTimeout, err = time.ParseDuration(timeoutStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid timeout parameter: %v", err), http.StatusBadRequest)
			return
		}
	}

	ctx := r.Context()
	if customTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, customTimeout)
		defer cancel()
	}

	streamParam := r.URL.Query().Get("stream")
	acceptHeader := r.Header.Get("Accept")
	isStreaming := streamParam == "true" || acceptHeader == "text/event-stream"

	if isStreaming {
		out, err := node.DiscoverRemoteServicesStream(ctx, serviceType, serviceName)
		if err != nil {
			logger.Errorf("Failed to start streaming service discovery: %v", err)
			http.Error(w, fmt.Sprintf("Failed to start streaming service discovery: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		for {
			select {
			case <-ctx.Done():
				return
			case dp, ok := <-out:
				if !ok {
					if _, err := fmt.Fprintf(w, "event: done\ndata: {}\n\n"); err != nil {
						logger.Errorf("Failed to write SSE done: %v", err)
					}
					flusher.Flush()
					return
				}
				data, err := json.Marshal(dp)
				if err != nil {
					logger.Errorf("Failed to marshal discovered provider: %v", err)
					continue
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
					logger.Errorf("Failed to write SSE data: %v", err)
					return
				}
				flusher.Flush()
			}
		}
	}

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit := 20
	offset := 0
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	providers, err := node.DiscoverRemoteServices(ctx, serviceType, serviceName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to discover services: %v", err), http.StatusInternalServerError)
		return
	}

	if offset >= len(providers) {
		providers = []*api.DiscoveredProvider{}
	} else {
		end := offset + limit
		if end > len(providers) || end < offset {
			end = len(providers)
		}
		providers = providers[offset:end]
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(providers); err != nil {
		logger.Errorf("Failed to encode providers: %v", err)
	}
}

func createEgressProxy(node *SamNode) http.Handler {
	transport := libp2phttp.NewTransport(node.Host)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			ctx := req.Context()
			ctx = network.WithAllowLimitedConn(ctx, "egress-proxy")
			*req = *req.WithContext(ctx)

			parts := strings.SplitN(req.URL.Path, "/", 6)
			if len(parts) < 5 {
				return
			}
			peerID := parts[2]
			pid, err := peer.Decode(peerID)
			if err == nil {
				if cond := node.Host.Network().Connectedness(pid); cond != network.Connected && cond != network.Limited {
					node.preparePeerAddrs(ctx, pid)
				}
			}
			serviceType := parts[3]
			serviceName := parts[4]
			upstreamPath := ""
			if len(parts) > 5 {
				upstreamPath = parts[5]
			}
			logger.Debugf("[Egress] Routing to peer: %s, svcType: %s, svcName: %s, upstream: %q", peerID, serviceType, serviceName, upstreamPath)

			req.URL.Scheme = "libp2p"
			req.URL.Host = peerID
			req.Host = peerID
			if len(parts) == 5 {
				req.URL.Path = fmt.Sprintf("/%s/%s", serviceType, serviceName)
			} else {
				req.URL.Path = fmt.Sprintf("/%s/%s/%s", serviceType, serviceName, upstreamPath)
			}
			req.URL.RawPath = ""
			logger.Debugf("[Proxy] Rewriting URL to libp2p://%s%s", req.URL.Host, req.URL.Path)
		},
		Transport: transport,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if node == nil {
			logger.Errorf("[Proxy] Node is nil, rejecting egress request.")
			http.Error(w, "Service Unavailable: Node Not Initialized", http.StatusServiceUnavailable)
			return
		}
		biscuitBytes := node.GetIdentity()
		if biscuitBytes == nil {
			logger.Errorf("[Proxy] Failed to load node identity for egress request, rejecting.")
			http.Error(w, "Service Unavailable: Missing Node Identity", http.StatusServiceUnavailable)
			return
		}

		r.Header.Set(api.HeaderSamBiscuit, base64.StdEncoding.EncodeToString(biscuitBytes))

		// Forwarded, not stripped: the agent claim is what lets the peer at the
		// other end authorize and audit the agent rather than just this node.
		// Replacing it with what the local gateway said also drops any value a
		// caller that is not the gateway tried to set.
		if agentID := agentFromLocalGateway(r); agentID != "" {
			r.Header.Set(api.HeaderSamAgent, agentID)
		} else {
			r.Header.Del(api.HeaderSamAgent)
		}

		// Strip the local sidecar gate header before forwarding off-node; a caller-supplied
		// "Authorization" header passes straight through untouched as the destination's own credential.
		r.Header.Del(api.HeaderSamAuthentication)

		proxy.ServeHTTP(w, r)
	})
}
