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

package protocol

import (
	"context"
	"fmt"
	"os"

	internaldb "sam/internal/db"
)

// VouchGate is a FederationGate that allows a peer only when a valid vouch
// record exists in the local bbolt store for the given federation.
// Entries in the vouch bucket are keyed by requester PeerID.
// If the key is absent the peer is denied.
type VouchGate struct {
	store internaldb.Store
}

// NewVouchGate creates a gate backed by the given store (federation-scoped).
func NewVouchGate(store internaldb.Store) *VouchGate {
	return &VouchGate{store: store}
}

// NewVouchGateForFederation opens (or lazily creates) the federation-scoped
// bbolt store and returns a VouchGate.  The caller is responsible for calling
// the returned close function when done.
func NewVouchGateForFederation(federationID string) (*VouchGate, func() error, error) {
	mgr, err := internaldb.NewManager()
	if err != nil {
		return nil, nil, fmt.Errorf("creating federation manager: %w", err)
	}
	store, err := mgr.Store(federationID)
	if err != nil {
		_ = mgr.Close()
		return nil, nil, fmt.Errorf("opening federation %q store: %w", federationID, err)
	}
	return NewVouchGate(store), mgr.Close, nil
}

// Allow returns nil when the requester's PeerID has a vouch record in the
// federation store, or a descriptive error when it is absent.
func (g *VouchGate) Allow(ctx context.Context, peerID string, _ string) error {
	if peerID == "" {
		return fmt.Errorf("empty peer ID")
	}
	_, err := g.store.Get(ctx, internaldb.BucketVouches, peerID)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("peer %s has no vouch in this federation", peerID)
		}
		return fmt.Errorf("checking vouch for peer %s: %w", peerID, err)
	}
	return nil
}
