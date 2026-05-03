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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

func startSidecarServer(node *SamNode, addr, token, certFile, keyFile, caFile string) {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)

	// Protected endpoints
	mux.Handle("/sam/service/register", withAuth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRegisterService(node, w, r)
	})))
	mux.Handle("/sam/service/unregister", withAuth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleUnregisterService(node, w, r)
	})))
	mux.Handle("/sam/service/discover", withAuth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDiscoverService(node, w, r)
	})))

	// Mount MCP handler
	mcpHandler := NewMCPHandler(node)
	mux.Handle("/", mcpHandler)

	server := &http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Errorf("Failed to listen on %s: %v", addr, err)
		return
	}

	actualAddr := listener.Addr().String()

	if (certFile != "") != (keyFile != "") {
		logger.Errorf("Both --tls-cert and --tls-key must be provided to enable TLS")
		return
	}

	if certFile != "" && keyFile != "" {
		tlsConfig := &tls.Config{}
		isMTLS := false
		if caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				logger.Errorf("Failed to read CA cert: %v", err)
				return
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			isMTLS = true
		}

		if !isMTLS && token == "" {
			logger.Errorf("Token is mandatory when not using mTLS")
			return
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
			logger.Errorf("Token is mandatory when not using mTLS")
			return
		}
		logger.Infof("Starting MCP server on TCP address %s", actualAddr)
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				logger.Errorf("Sidecar API server error: %v", err)
			}
		}()
	}
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

func withAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			// If token is empty, we assume mTLS is handling authentication.
			// startSidecarServer enforces that token is present if mTLS is not used.
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
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

	var req ServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ServiceName == "" {
		http.Error(w, "service_name is required", http.StatusBadRequest)
		return
	}

	if err := node.RegisterService(r.Context(), req.ServiceName); err != nil {
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

	var req ServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ServiceName == "" {
		http.Error(w, "service_name is required", http.StatusBadRequest)
		return
	}

	if err := node.UnregisterService(r.Context(), req.ServiceName); err != nil {
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
	if serviceName == "" {
		http.Error(w, "name query parameter is required", http.StatusBadRequest)
		return
	}

	providers, err := node.FindProviders(r.Context(), serviceName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to discover services: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(providers); err != nil {
		logger.Errorf("Failed to encode providers: %v", err)
	}
}
