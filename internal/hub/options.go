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

package hub

import (
	"fmt"
	"time"

	"github.com/google/sam/api"
)

const (
	DefaultOIDCIssuer  = "https://accounts.google.com"
	DefaultMeshName    = "public-mesh"
	DefaultPolicyFile  = "policies.yaml"
	DefaultKeysDBPath  = "keys.db"
	DefaultBindAddress = ":9090"
)

// Options holds configuration settings for the Hub.
type Options struct {
	OIDCIssuer            string
	ClientID              string
	BiscuitHex            string
	ListenAddrs           []string
	MeshName              string
	InsecureSkipTLSVerify bool
	PolicyFile            string
	KeyRotationInterval   time.Duration
	KeyGracePeriod        time.Duration
	KeysDBPath            string
	BindAddress           string
	AdminToken            string
	TLSCertFile           string
	TLSKeyFile            string
	TLSCAFile             string
	ExternalMultiaddrs    []string
	AllowedAudiences      []string
	AllowLoopback         bool
	Policy                *api.PolicyConfig
}

// Default sets non-zero default values for options.
func (o *Options) Default() {
	if o.OIDCIssuer == "" {
		o.OIDCIssuer = DefaultOIDCIssuer
	}
	if o.MeshName == "" {
		o.MeshName = DefaultMeshName
	}
	if o.PolicyFile == "" {
		o.PolicyFile = DefaultPolicyFile
	}
	if o.KeysDBPath == "" {
		o.KeysDBPath = DefaultKeysDBPath
	}
	if o.BindAddress == "" {
		o.BindAddress = DefaultBindAddress
	}
	if o.KeyGracePeriod == 0 {
		o.KeyGracePeriod = 24 * time.Hour
	}
}

// Validate checks that all required options are set and valid.
func (o *Options) Validate() error {
	if o.KeysDBPath == "" {
		return fmt.Errorf("keys database path is required")
	}
	if o.Policy == nil {
		return fmt.Errorf("policy configuration is required")
	}
	return nil
}
