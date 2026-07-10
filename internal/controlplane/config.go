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

package controlplane

import (
	"fmt"
	"time"
)

// Options holds configuration for the control plane.
type Options struct {
	ListenAddr            string
	DriverName            string
	DataSourceName        string
	OIDCIssuer            string
	AllowedAudiences      []string
	LeaseDuration         time.Duration
	KeyRotationInterval   time.Duration
	KeyGracePeriod        time.Duration
	InsecureSkipTLSVerify bool
	BiscuitTimeout        time.Duration
	PolicyPath            string // Optional: path to bootstrap policy configuration
}

// Default sets default values for control plane options.
func (o *Options) Default() {
	if o.ListenAddr == "" {
		o.ListenAddr = "0.0.0.0:8080"
	}
	if o.DriverName == "" {
		o.DriverName = "sqlite"
		o.DataSourceName = "control-plane.db"
	}
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = 60 * time.Second
	}
	if o.KeyRotationInterval <= 0 {
		o.KeyRotationInterval = 24 * time.Hour
	}
	if o.KeyGracePeriod <= 0 {
		o.KeyGracePeriod = 1 * time.Hour
	}
}

// Validate ensures options are valid.
func (o *Options) Validate() error {
	if o.DriverName == "" {
		return fmt.Errorf("DriverName must be specified")
	}
	if o.DataSourceName == "" {
		return fmt.Errorf("DataSourceName must be specified")
	}
	return nil
}
