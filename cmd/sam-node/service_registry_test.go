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
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/sam/api"
	"github.com/ipfs/go-cid"
)

type fakeDHT struct {
	calls   []cid.Cid
	failNth int
	count   int32
}

func (f *fakeDHT) Provide(ctx context.Context, c cid.Cid, _ bool) error {
	n := atomic.AddInt32(&f.count, 1)
	f.calls = append(f.calls, c)
	if f.failNth > 0 && int(n) == f.failNth {
		return errors.New("fake dht failure")
	}
	return nil
}

type fakeService struct {
	info          *api.ServiceInfo
	initCalls     int
	teardownCalls int
	initErr       error
	handler       http.Handler
}

func (f *fakeService) Info() *api.ServiceInfo { return f.info }
func (f *fakeService) Init(ctx context.Context) error {
	f.initCalls++
	return f.initErr
}
func (f *fakeService) Handler() http.Handler { return f.handler }
func (f *fakeService) Teardown() error {
	f.teardownCalls++
	return nil
}

func newFakeSvc(name string, st api.ServiceType) *fakeService {
	return &fakeService{
		info:    &api.ServiceInfo{Name: name, Type: st},
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
	}
}

// newServiceRegistryForTest builds a registry against the fake DHT for tests.
func newServiceRegistryForTest(d dhtProvider) *ServiceRegistry {
	return &ServiceRegistry{
		services: map[string]Service{},
		dht:      d,
	}
}

func TestServiceRegistry_RegisterCallsInitThenProvide(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if svc.initCalls != 1 {
		t.Errorf("Init called %d times, want 1", svc.initCalls)
	}
	if len(dht.calls) != 2 {
		t.Fatalf("Provide called %d times, want 2 (name + type CID)", len(dht.calls))
	}
}

func TestServiceRegistry_InitErrorBlocksProvideAndInsertion(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	svc.initErr = errors.New("init failed")
	if err := r.Register(context.Background(), svc); err == nil {
		t.Fatal("expected error from Register, got nil")
	}
	if len(dht.calls) != 0 {
		t.Errorf("Provide called %d times after Init failure, want 0", len(dht.calls))
	}
	if _, ok := r.Get("demo"); ok {
		t.Error("service should not be in map after Init failure")
	}
}

func TestServiceRegistry_UnregisterRemovesAndCallsTeardown(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	_ = r.Register(context.Background(), svc)
	if err := r.Unregister(context.Background(), "demo"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if svc.teardownCalls != 1 {
		t.Errorf("Teardown called %d times, want 1", svc.teardownCalls)
	}
	if _, ok := r.Get("demo"); ok {
		t.Error("service still present after Unregister")
	}
}

func TestServiceRegistry_UnregisterUnknownIsNoOp(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	if err := r.Unregister(context.Background(), "missing"); err != nil {
		t.Fatalf("Unregister missing: %v", err)
	}
}

func TestServiceRegistry_ListFiltersByType(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	_ = r.Register(context.Background(), newFakeSvc("a", api.ServiceType_SERVICE_TYPE_MCP))
	_ = r.Register(context.Background(), newFakeSvc("b", api.ServiceType_SERVICE_TYPE_INFERENCE))

	all := r.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)
	if len(all) != 2 {
		t.Errorf("List(all): got %d, want 2", len(all))
	}
	mcpOnly := r.List(api.ServiceType_SERVICE_TYPE_MCP)
	if len(mcpOnly) != 1 || mcpOnly[0].Name != "a" {
		t.Errorf("List(MCP): got %v, want [a]", mcpOnly)
	}
}

func TestServiceRegistry_TeardownAllContinuesOnError(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	a := newFakeSvc("a", api.ServiceType_SERVICE_TYPE_MCP)
	b := newFakeSvc("b", api.ServiceType_SERVICE_TYPE_MCP)
	_ = r.Register(context.Background(), a)
	_ = r.Register(context.Background(), b)

	r.TeardownAll()

	if a.teardownCalls != 1 || b.teardownCalls != 1 {
		t.Errorf("teardown calls: a=%d b=%d, want both 1", a.teardownCalls, b.teardownCalls)
	}
	if len(r.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)) != 0 {
		t.Error("registry not empty after TeardownAll")
	}
}
