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
	"testing"

	"github.com/google/sam/api"
)

func TestParseAndStringifyCatalogType(t *testing.T) {
	got, err := api.ParseServiceType("catalog")
	if err != nil {
		t.Fatalf("ParseServiceType(catalog): %v", err)
	}
	if got != api.ServiceType_SERVICE_TYPE_CATALOG {
		t.Fatalf("got %v, want SERVICE_TYPE_CATALOG", got)
	}
	s, err := api.ServiceTypeToString(api.ServiceType_SERVICE_TYPE_CATALOG)
	if err != nil {
		t.Fatalf("ServiceTypeToString(CATALOG): %v", err)
	}
	if s != "catalog" {
		t.Fatalf("got %q, want \"catalog\"", s)
	}
}

func TestServiceAnnounceTypeExists(t *testing.T) {
	// Compile-time check that the generated struct + fields exist.
	a := &api.ServiceAnnounce{
		Type:      api.ServiceType_SERVICE_TYPE_MCP,
		Name:      "x",
		PeerId:    "p",
		Addrs:     []string{"/ip4/127.0.0.1/tcp/1"},
		Timestamp: 1,
		TtlMs:     2,
		Signature: []byte{0x1},
	}
	if a.Name != "x" {
		t.Fatal("unexpected")
	}
}
