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
	"net/http"
	"os"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// startHTTPServer starts the HTTP/HTTPS server for metrics, healthz, and admin commands.
func startHTTPServer(h *Hub, bindAddr string, adminToken string, tlsCertFile string, tlsKeyFile string, tlsCAFile string, isHubReady *atomic.Bool) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if isHubReady.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
		}
	})

	mux.HandleFunc("/admin/ban", func(w http.ResponseWriter, r *http.Request) {
		if adminToken != "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer "+adminToken {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		handleBan(h)(w, r)
	})

	server := &http.Server{
		Addr:    bindAddr,
		Handler: mux,
	}

	// Configure TLS if requested
	if tlsCertFile != "" && tlsKeyFile != "" {
		tlsConfig := &tls.Config{}
		if tlsCAFile != "" {
			caCert, err := os.ReadFile(tlsCAFile)
			if err != nil {
				logger.Fatalf("Failed to read CA cert: %v", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			logger.Info("mTLS enabled for admin service")
		}
		server.TLSConfig = tlsConfig

		logger.Infof("Starting HTTPS server on %s", bindAddr)
		go func() {
			if err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Errorf("HTTPS server failed: %v", err)
			}
		}()
	} else {
		logger.Infof("Starting HTTP server on %s", bindAddr)
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Errorf("HTTP server failed: %v", err)
			}
		}()
	}
}
