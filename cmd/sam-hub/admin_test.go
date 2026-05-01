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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/sam/api"
)

type mockHubAdmin struct {
	publishedEvents []*api.MeshEvent
	publishErr      error
}

func (m *mockHubAdmin) PublishEvent(ctx context.Context, event *api.MeshEvent) error {
	if m.publishErr != nil {
		return m.publishErr
	}
	m.publishedEvents = append(m.publishedEvents, event)
	return nil
}

func TestHandleBan(t *testing.T) {
	mockAdmin := &mockHubAdmin{}
	handler := handleBan(mockAdmin)

	// Test valid request
	req, err := http.NewRequest("POST", "/admin/ban?peer=test-peer-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if len(mockAdmin.publishedEvents) != 1 {
		t.Errorf("expected 1 published event, got %d", len(mockAdmin.publishedEvents))
	}

	event := mockAdmin.publishedEvents[0]
	if event.Type != api.MeshEvent_BANNED {
		t.Errorf("expected BANNED event, got %v", event.Type)
	}
	if event.PeerId != "test-peer-id" {
		t.Errorf("expected peer ID test-peer-id, got %s", event.PeerId)
	}

	// Test invalid method
	req, err = http.NewRequest("GET", "/admin/ban?peer=test-peer-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusMethodNotAllowed)
	}

	// Test missing parameter
	req, err = http.NewRequest("POST", "/admin/ban", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}
