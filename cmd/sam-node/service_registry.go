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
	"sync"

	"github.com/google/sam/api"
	"github.com/ipfs/go-cid"
)

// dhtProvider is the narrow DHT surface ServiceRegistry depends on.
// Production wires this to *dht.IpfsDHT; tests use a fake.
type dhtProvider interface {
	Provide(ctx context.Context, c cid.Cid, broadcast bool) error
}

// ServiceRegistry is the type-agnostic owner of registered services.
type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]Service
	dht      dhtProvider
}

func NewServiceRegistry(d dhtProvider) *ServiceRegistry {
	return &ServiceRegistry{
		services: map[string]Service{},
		dht:      d,
	}
}

// Register initialises a service, advertises it on the DHT, and inserts it
// into the map. Init runs before Provide so a failed handler-build never
// briefly advertises an unservable name.
func (r *ServiceRegistry) Register(ctx context.Context, svc Service) error {
	info := svc.Info()
	if info.Type == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return fmt.Errorf("cannot register service with unspecified type")
	}

	if err := svc.Init(ctx); err != nil {
		return fmt.Errorf("init %s: %w", info.Name, err)
	}

	srvNameCID, err := serviceNameToCID(info.Type, info.Name)
	if err != nil {
		return err
	}
	srvTypeCID, err := serviceTypeToCID(info.Type)
	if err != nil {
		return err
	}

	if err := r.dht.Provide(ctx, srvNameCID, true); err != nil {
		logger.Warnf("[ServiceRegistry] DHT Provide (name) for %s: %v", info.Name, err)
	}
	if err := r.dht.Provide(ctx, srvTypeCID, true); err != nil {
		logger.Warnf("[ServiceRegistry] DHT Provide (type) for %s: %v", info.Name, err)
	}

	r.mu.Lock()
	r.services[info.Name] = svc
	r.mu.Unlock()

	logger.Infof("[ServiceRegistry] Registered %s/%s (name CID: %s, type CID: %s)", info.Type, info.Name, srvNameCID, srvTypeCID)
	return nil
}

// Unregister removes the service from the map and calls Teardown.
// Unknown names are a no-op.
func (r *ServiceRegistry) Unregister(ctx context.Context, name string) error {
	r.mu.Lock()
	svc, ok := r.services[name]
	delete(r.services, name)
	r.mu.Unlock()
	if !ok {
		return nil
	}
	if err := svc.Teardown(); err != nil {
		logger.Errorf("[ServiceRegistry] Teardown %s: %v", name, err)
	}
	logger.Infof("[ServiceRegistry] Unregistered %s", name)
	return nil
}

// Get returns the service registered under name, if any.
func (r *ServiceRegistry) Get(name string) (Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	svc, ok := r.services[name]
	return svc, ok
}

// List returns the ServiceInfo for every registered service, optionally
// filtered by type. SERVICE_TYPE_UNSPECIFIED means "all types."
func (r *ServiceRegistry) List(typeFilter api.ServiceType) []*api.ServiceInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []*api.ServiceInfo{}
	for _, svc := range r.services {
		info := svc.Info()
		if typeFilter != api.ServiceType_SERVICE_TYPE_UNSPECIFIED && info.Type != typeFilter {
			continue
		}
		out = append(out, info)
	}
	return out
}

// insertService inserts a service into the registry without calling Init or
// advertising on the DHT. For tests only.
func (r *ServiceRegistry) insertService(svc Service) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services[svc.Info().Name] = svc
}

// TeardownAll calls Teardown on every registered service and clears the
// map. Per-service errors are logged; iteration continues.
func (r *ServiceRegistry) TeardownAll() {
	r.mu.Lock()
	svcs := r.services
	r.services = map[string]Service{}
	r.mu.Unlock()
	for name, svc := range svcs {
		if err := svc.Teardown(); err != nil {
			logger.Errorf("[ServiceRegistry] Teardown %s: %v", name, err)
		}
	}
}
