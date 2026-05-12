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
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strings"

	"github.com/google/sam/api"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// Service is the contract the ServiceRegistry and ingress server use.
// Implementations own all type-specific behaviour; the registry stays
// type-agnostic.
type Service interface {
	Info() *api.ServiceInfo
	Init(ctx context.Context) error
	Handler() http.Handler
	Teardown() error
}

// baseService is the shared embeddable. Holds the fields and default
// Init/Teardown behaviour every service kind needs. backend is typed as
// any because the proto-generated oneof interface is unexported.
type baseService struct {
	info    *api.ServiceInfo
	backend any
	handler http.Handler
	cmd     *exec.Cmd // nil for URL-backed
}

// newReverseProxyHandler builds a single-host reverse-proxy handler for a
// URL backend. Same code path as today's URL branch in RegisterService.
func newReverseProxyHandler(targetURL string) (http.Handler, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	return httputil.NewSingleHostReverseProxy(u), nil
}

func (b *baseService) Info() *api.ServiceInfo { return b.info }
func (b *baseService) Handler() http.Handler  { return b.handler }

// Init builds the ingress handler for the backend. URL -> reverse-proxy,
// Command -> StdioBridge. MCPService extends this; it does not replace it.
func (b *baseService) Init(ctx context.Context) error {
	switch x := b.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		h, err := newReverseProxyHandler(x.TargetUrl)
		if err != nil {
			return err
		}
		b.handler = h
	case *api.RegisterServiceRequest_Command:
		h, cmd, err := createStdioBridgeHandler(x.Command)
		if err != nil {
			return err
		}
		b.handler = h
		b.cmd = cmd
	default:
		return fmt.Errorf("unsupported backend type %T", b.backend)
	}
	return nil
}

// Teardown kills the child process if any. Safe to call when cmd is nil
// or already dead.
func (b *baseService) Teardown() error {
	if b.cmd == nil || b.cmd.Process == nil {
		return nil
	}
	return b.cmd.Process.Kill()
}

// InferenceService and A2AService are zero-override embeddings. They exist
// so the factory produces a distinct type per ServiceType, leaving room for
// future per-kind behaviour without churn.
type InferenceService struct{ baseService }
type A2AService struct{ baseService }

func NewServiceFromRequest(req *api.RegisterServiceRequest) (Service, error) {
	info := req.Service
	switch info.Type {
	case api.ServiceType_SERVICE_TYPE_MCP:
		return &MCPService{baseService: baseService{info: info, backend: req.Backend}}, nil
	case api.ServiceType_SERVICE_TYPE_INFERENCE:
		return &InferenceService{baseService: baseService{info: info, backend: req.Backend}}, nil
	case api.ServiceType_SERVICE_TYPE_A2A:
		return &A2AService{baseService: baseService{info: info, backend: req.Backend}}, nil
	default:
		return nil, fmt.Errorf("unspecified or unsupported service type: %v", info.Type)
	}
}

// buildRegisterRequest converts a static-config service entry into the
// RegisterServiceRequest the registry consumes.
func buildRegisterRequest(sCfg api.ServiceConfig) (*api.RegisterServiceRequest, error) {
	sType, err := parseServiceType(sCfg.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid service type %q for service %s: %w", sCfg.Type, sCfg.Name, err)
	}
	req := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{
			Type:        sType,
			Name:        sCfg.Name,
			Description: sCfg.Description,
		},
	}
	switch {
	case sCfg.TargetURL != "":
		req.Backend = &api.RegisterServiceRequest_TargetUrl{TargetUrl: sCfg.TargetURL}
	case len(sCfg.Command) > 0:
		req.Backend = &api.RegisterServiceRequest_Command{
			Command: &api.CommandBackend{
				Command: sCfg.Command,
				Env:     sCfg.Env,
			},
		}
	default:
		return nil, fmt.Errorf("service %s has no backend specified", sCfg.Name)
	}
	return req, nil
}

func serviceTypeToString(t api.ServiceType) (string, error) {
	switch t {
	case api.ServiceType_SERVICE_TYPE_MCP:
		return "mcp", nil
	case api.ServiceType_SERVICE_TYPE_INFERENCE:
		return "inference", nil
	case api.ServiceType_SERVICE_TYPE_A2A:
		return "a2a", nil
	default:
		return "", fmt.Errorf("invalid or unspecified service type")
	}
}

func parseServiceType(s string) (api.ServiceType, error) {
	switch strings.ToLower(s) {
	case "mcp":
		return api.ServiceType_SERVICE_TYPE_MCP, nil
	case "inference":
		return api.ServiceType_SERVICE_TYPE_INFERENCE, nil
	case "a2a":
		return api.ServiceType_SERVICE_TYPE_A2A, nil
	default:
		return api.ServiceType_SERVICE_TYPE_UNSPECIFIED, fmt.Errorf("invalid service type: %s", s)
	}
}

// serviceKeyToCID hashes "sam:service[:part]..." into a DHT rendezvous CID.
func serviceKeyToCID(parts ...string) (cid.Cid, error) {
	srvKey := strings.Join(append([]string{"sam:service"}, parts...), ":")
	hash, err := multihash.Sum([]byte(srvKey), multihash.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, hash), nil
}

func serviceNameToCID(serviceType api.ServiceType, serviceName string) (cid.Cid, error) {
	srvTypeStr, err := serviceTypeToString(serviceType)
	if err != nil {
		return cid.Undef, err
	}
	return serviceKeyToCID(srvTypeStr, serviceName)
}

func serviceTypeToCID(serviceType api.ServiceType) (cid.Cid, error) {
	srvTypeStr, err := serviceTypeToString(serviceType)
	if err != nil {
		return cid.Undef, err
	}
	return serviceKeyToCID(srvTypeStr)
}
