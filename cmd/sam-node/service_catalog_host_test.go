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

func TestNewServiceFromRequestCatalog(t *testing.T) {
	req := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_CATALOG, Name: "catalog"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://127.0.0.1:9"},
	}
	svc, err := NewServiceFromRequest(req)
	if err != nil {
		t.Fatalf("CATALOG should be hostable: %v", err)
	}
	if _, ok := svc.(*MCPService); !ok {
		t.Fatalf("CATALOG should be served via MCPService, got %T", svc)
	}
}
