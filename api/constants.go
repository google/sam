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

package api

import "github.com/libp2p/go-libp2p/core/protocol"

const EnrollProtocolID protocol.ID = "/sam/enroll/1.0.0"
const MCPProtocolID protocol.ID = "/sam/mcp/1.0.0"
const GossipEvents = "/sam/mesh/events/v1"
const AuthProtocolID protocol.ID = "/sam/auth/1.0.0"

const DefaultAudience = "sam-mesh-audience"

// Biscuit fact names
const (
	FactExpiration    = "expiration"
	FactNode          = "node"
	FactClientPeerID  = "client_peer_id"
	FactGroup         = "group"
	FactRole          = "role"
	FactUser          = "user"
	FactMCPTool       = "allow_mcp_tool"
	FactNetworkTarget = "allow_network_target"
)
