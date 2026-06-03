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
	"fmt"
	"net/http"
	"time"

	"github.com/google/sam/api"
)

// HubAdmin defines the interface needed by admin handlers.
type HubAdmin interface {
	PublishEvent(ctx context.Context, event *api.MeshEvent) error
}

// handleBan returns a handler for the /admin/ban endpoint.
func handleBan(admin HubAdmin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		peerID := r.URL.Query().Get("peer")
		logger.Infof("[Admin API] Received ban request for peer: %s", peerID)
		
		if peerID == "" {
			http.Error(w, "Missing peer parameter", http.StatusBadRequest)
			return
		}

		// Create MeshEvent_BANNED
		event := &api.MeshEvent{
			Type:      api.MeshEvent_BANNED,
			PeerId:    peerID,
			Timestamp: time.Now().UnixMilli(),
		}

		logger.Infof("[Admin API] Publishing ban event for peer: %s", peerID)
		if err := admin.PublishEvent(r.Context(), event); err != nil {
			logger.Errorf("[Admin API] Failed to publish event: %v", err)
			http.Error(w, fmt.Sprintf("Failed to publish event: %v", err), http.StatusInternalServerError)
			return
		}

		logger.Infof("[Admin API] Successfully published ban event for peer: %s", peerID)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Published BANNED event for peer %s", peerID)
	}
}
