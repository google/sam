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
	"strconv"
	"strings"
	"time"

	"github.com/google/sam/api"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
)

func StartSidecarServer(node *SamNode, addr, token, certFile, keyFile, caFile string) (*http.Server, error) {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)

	// Protected endpoints
	mux.Handle("/sam/service/register", withAuth(token, withMeshConnection(node, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRegisterService(node, w, r)
	}))))
	mux.Handle("/sam/service/unregister", withAuth(token, withMeshConnection(node, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleUnregisterService(node, w, r)
	}))))
	mux.Handle("/sam/service/discover", withAuth(token, withMeshConnection(node, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDiscoverService(node, w, r)
	}))))

	// Mount Egress Proxy
	mux.Handle("/sam/", withAuth(token, withMeshConnection(node, createEgressProxy(node))))

	// Mount MCP handler
	mcpHandler := NewMCPHandler(node)
	mux.Handle("/", withAuth(token, withMeshConnection(node, mcpHandler)))

	server := &http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	actualAddr := listener.Addr().String()
	node.BoundHTTPAddr = actualAddr

	if (certFile != "") != (keyFile != "") {
		_ = listener.Close()
		return nil, fmt.Errorf("both --tls-cert and --tls-key must be provided to enable TLS")
	}

	if certFile != "" && keyFile != "" {
		tlsConfig := &tls.Config{}
		isMTLS := false
		if caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				_ = listener.Close()
				return nil, fmt.Errorf("failed to read CA cert: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			isMTLS = true
		}

		if !isMTLS && token == "" {
			_ = listener.Close()
			return nil, fmt.Errorf("token is mandatory when not using mTLS")
		}

		server.TLSConfig = tlsConfig
		logger.Infof("Starting MCP server on TCP address %s (with TLS Sidecar)", actualAddr)
		go func() {
			if err := server.ServeTLS(listener, certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Errorf("Sidecar API server error: %v", err)
			}
		}()
	} else {
		if token == "" {
			_ = listener.Close()
			return nil, fmt.Errorf("token is mandatory when not using mTLS")
		}
		logger.Infof("Starting MCP server on TCP address %s", actualAddr)
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				logger.Errorf("Sidecar API server error: %v", err)
			}
		}()
	}
	return server, nil
}

func StartUnauthSidecarServer(hubURL, addr, certFile, keyFile string) (*http.Server, error) {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)

	// Mount Unauthenticated MCP handler
	mcpHandler := NewUnauthenticatedMCPHandler(hubURL)
	mux.Handle("/", mcpHandler)

	server := &http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	actualAddr := listener.Addr().String()

	if (certFile != "") != (keyFile != "") {
		_ = listener.Close()
		return nil, fmt.Errorf("both --tls-cert and --tls-key must be provided to enable TLS")
	}

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

func withAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("[SidecarAuth] Incoming request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		if token == "" {
			// If token is empty, we assume mTLS is handling authentication.
			// StartSidecarServer enforces that token is present if mTLS is not used.
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logger.Warnf("[SidecarAuth] Request %s %s rejected: missing Authorization header", r.Method, r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		if parts[1] != token {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type ServiceRequest struct {
	ServiceName string `json:"service_name"`
}

func handleRegisterService(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

		// Map X-Sam-Authorization to Authorization header for the remote service,
		// and delete the local sidecar Authorization header to prevent leaking it.
		if upstreamAuth := r.Header.Get(api.HeaderSamAuthorization); upstreamAuth != "" {
			r.Header.Set("Authorization", upstreamAuth)
			r.Header.Del(api.HeaderSamAuthorization)
		} else {
			r.Header.Del("Authorization")
		}

		proxy.ServeHTTP(w, r)
	})
}
