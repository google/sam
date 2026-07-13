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

package router

import (
	"fmt"
	"time"
)

// Options holds configuration details for the sam-router.
type Options struct {
	ControlPlaneURL    string
	ListenAddrs        []string
	ExternalAddrs      []string
	KeysSyncInterval   time.Duration
	LeaseRenewInterval time.Duration
	OIDCProvider       string // For OIDC enrollment
	OIDCToken          string // OIDC JWT token for enrollment
	BootstrapToken     string // Pre-shared bootstrap token for enrollment
	BootstrapTokenPath string // File path containing pre-shared bootstrap token
	JWTPath            string // File path containing OIDC JWT token
	KeysDBPath         string // Path to save peer private key
	AllowLoopback      bool
	BiscuitTimeout     time.Duration
	LogVerbose         bool
	DHTProviderAddrTTL time.Duration
	DHTMaxRecordAge    time.Duration
}

// Default sets default values for options.
func (o *Options) Default() {
	if o.ControlPlaneURL == "" {
		o.ControlPlaneURL = "http://127.0.0.1:8080"
	}
	if len(o.ListenAddrs) == 0 {
		o.ListenAddrs = []string{"/ip4/0.0.0.0/tcp/5001", "/ip6/::/tcp/5001"}
	}
	if o.KeysSyncInterval <= 0 {
		o.KeysSyncInterval = 5 * time.Minute
	}
	if o.LeaseRenewInterval <= 0 {
		o.LeaseRenewInterval = 30 * time.Second
	}
	if o.KeysDBPath == "" {
		o.KeysDBPath = "router.key"
	}
	if o.BiscuitTimeout <= 0 {
		o.BiscuitTimeout = 100 * time.Millisecond
	}
}

// Validate ensures options are valid.
func (o *Options) Validate() error {
	if o.ControlPlaneURL == "" {
		return fmt.Errorf("ControlPlaneURL must be specified")
	}
	return nil
}
