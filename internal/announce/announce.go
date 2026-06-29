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

package announce

import (
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// TTL is the per-entry lifetime (~3x the 5-min reprovide tick).
const TTL = 15 * time.Minute

// Build assembles an unsigned announce for a local service.
func Build(info *api.ServiceInfo, peerID peer.ID, addrs []string, now time.Time, ttl time.Duration) *api.ServiceAnnounce {
	return &api.ServiceAnnounce{
		Type:      info.Type,
		Name:      info.Name,
		PeerId:    peerID.String(),
		Addrs:     addrs,
		Timestamp: now.UnixMilli(),
		TtlMs:     ttl.Milliseconds(),
	}
}

// Sign signs the announce over its signature-cleared marshalling.
func Sign(priv crypto.PrivKey, a *api.ServiceAnnounce) error {
	a.Signature = nil
	data, err := proto.Marshal(a)
	if err != nil {
		return err
	}
	sig, err := priv.Sign(data)
	if err != nil {
		return err
	}
	a.Signature = sig
	return nil
}

// Verify checks the signature against the key derived from PeerId.
func Verify(a *api.ServiceAnnounce) (bool, error) {
	pid, err := peer.Decode(a.PeerId)
	if err != nil {
		return false, err
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil {
		return false, err
	}
	sig := a.Signature
	a.Signature = nil
	data, err := proto.Marshal(a)
	a.Signature = sig // restore
	if err != nil {
		return false, err
	}
	return pub.Verify(data, sig)
}
