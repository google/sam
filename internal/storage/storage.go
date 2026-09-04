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

package storage

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/google/sam/api"
)

var (
	ErrNotFound = errors.New("not found")

	// ErrNodeBanned and ErrNodeSessionExpired are the two ways an enrolled node
	// stops being servable. See EnrolledNode.CheckAdmission.
	ErrNodeBanned         = errors.New("node is banned")
	ErrNodeSessionExpired = errors.New("node session expired")
)

// KeyPair holds cryptographic key information.
type KeyPair struct {
	Private    ed25519.PrivateKey
	Public     ed25519.PublicKey
	Expiration time.Time
}

// RouterLease represents a router registered with the control plane.
type RouterLease struct {
	PeerID         string
	Addresses      []string
	LastRenewal    time.Time
	ExpiresAt      time.Time
	ConnectedPeers []string
	DHTSize        int
}

// User represents a human identity in the mesh.
type User struct {
	ID        string
	Email     string
	Role      string
	CreatedAt time.Time
}

// EnrolledNode represents a node enrolled in the mesh.
type EnrolledNode struct {
	PeerID         string
	PublicKey      []byte
	Biscuit        []byte
	Role           string
	EnrollmentType string
	ClaimsJSON     string
	OwnerID        string
	// Labels are the attested key=value claims minted into the node's
	// biscuit; kept on the record so token refreshes re-mint them unchanged.
	Labels     map[string]string
	EnrolledAt time.Time
	ExpiresAt  time.Time
	Banned     bool
}

// CheckAdmission reports whether the control plane may still serve this node.
// Enrollment is bounded by two independent conditions, an explicit ban and the
// end of the OIDC session, and every path that acts on an enrolled node has to
// apply both: checking only Banned lets a node whose session lapsed keep
// reading mesh state until someone bans it by hand.
func (n *EnrolledNode) CheckAdmission(now time.Time) error {
	if n.Banned {
		return ErrNodeBanned
	}
	if !n.ExpiresAt.IsZero() && now.After(n.ExpiresAt) {
		return ErrNodeSessionExpired
	}
	return nil
}

// BootstrapToken represents a pre-shared token for node enrollment.
type BootstrapToken struct {
	ID          string
	TokenHash   string
	Role        string
	OwnerID     string
	MaxUsages   int
	UsagesCount int
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// EnrollmentRequest represents a pending or resolved node registration request (CSR).
type EnrollmentRequest struct {
	ID        string
	PeerID    string
	PublicKey []byte
	TokenID   string
	Status    api.EnrollmentStatus
	// Labels are the operator-declared key=value claims, surfaced to the
	// approving admin; approval attests them into the minted biscuit.
	Labels       map[string]string
	BiscuitToken []byte
	CreatedAt    time.Time
	ResolvedAt   *time.Time
	ResolvedBy   string
}

// Store defines the persistent operations for the SAM control plane.
type Store interface {
	// Ping checks the health of the underlying database connection.
	Ping(ctx context.Context) error

	// GetCurrentKey retrieves the active key pair for biscuit signing.
	GetCurrentKey(ctx context.Context) (ed25519.PrivateKey, ed25519.PublicKey, error)

	// GetAllValidKeys retrieves the active key pair and any non-expired historical key pairs.
	GetAllValidKeys(ctx context.Context) ([]KeyPair, error)

	// RotateKeys rotates the current key to a new key pair and sets the expiration of the old key.
	RotateKeys(ctx context.Context, newPriv ed25519.PrivateKey, newPub ed25519.PublicKey, gracePeriod time.Duration) error

	// ClaimKeyRotation atomically claims the next scheduled key-rotation
	// window, so multiple control-plane replicas sharing one database rotate
	// keys exactly once per interval instead of racing independently. It
	// returns true if the caller won the claim (advancing the deadline by
	// interval), false if another replica already claimed this window.
	ClaimKeyRotation(ctx context.Context, now time.Time, interval time.Duration) (bool, error)

	// ReleaseKeyRotationClaim reverts a claim won via ClaimKeyRotation with
	// the same now/interval back to its pre-claim deadline, so the window
	// can be retried without waiting a full interval. Callers use this when
	// the rotation that followed a successful claim failed.
	ReleaseKeyRotationClaim(ctx context.Context, now time.Time, interval time.Duration) error

	// SaveInitialKey sets the initial key pair if no keys exist yet.
	SaveInitialKey(ctx context.Context, priv ed25519.PrivateKey, pub ed25519.PublicKey) error

	// SaveUser creates or updates a User.
	SaveUser(ctx context.Context, user *User) error

	// GetUser retrieves a User by ID.
	GetUser(ctx context.Context, id string) (*User, error)

	// ListUsers retrieves all registered users.
	ListUsers(ctx context.Context) ([]User, error)

	// EnrollNode registers or updates a node enrollment.
	EnrollNode(ctx context.Context, node *EnrolledNode) error

	// GetNode retrieves node enrollment details.
	GetNode(ctx context.Context, peerID string) (*EnrolledNode, error)

	// SetNodeBanned updates the banned status of a node.
	SetNodeBanned(ctx context.Context, peerID string, banned bool) error

	// IsNodeBanned checks if a node is currently banned.
	IsNodeBanned(ctx context.Context, peerID string) (bool, error)

	// ListBannedPeerIDs returns the peer IDs of every currently banned node.
	// Callers publish this as the complete ban set (see
	// ControlPlaneInfoResponse.banned_peer_ids), so it must be the whole list
	// rather than a page of it.
	ListBannedPeerIDs(ctx context.Context) ([]string, error)

	// UpsertRouterLease updates or creates a lease for a sam-router.
	UpsertRouterLease(ctx context.Context, lease *RouterLease) error

	// GetActiveRouters retrieves all routers whose leases are still valid.
	GetActiveRouters(ctx context.Context) ([]RouterLease, error)

	// SaveMeshPolicy persists the mesh configurations.
	SaveMeshPolicy(ctx context.Context, roles []*api.PolicyRole, bindings []*api.PolicyBinding) error

	// GetMeshPolicy loads the mesh configurations.
	GetMeshPolicy(ctx context.Context) ([]*api.PolicyRole, []*api.PolicyBinding, error)

	// SaveBootstrapToken persists a new bootstrap token.
	SaveBootstrapToken(ctx context.Context, token *BootstrapToken) error

	// GetBootstrapToken retrieves a bootstrap token by its ID (sha256 hash).
	GetBootstrapToken(ctx context.Context, id string) (*BootstrapToken, error)

	// IncrementBootstrapTokenUsage increments the usage count of a token.
	IncrementBootstrapTokenUsage(ctx context.Context, id string) error

	// CreateEnrollmentRequest saves a new pending enrollment request.
	CreateEnrollmentRequest(ctx context.Context, req *EnrollmentRequest) error

	// GetEnrollmentRequest retrieves an enrollment request by PeerID.
	GetEnrollmentRequest(ctx context.Context, peerID string) (*EnrollmentRequest, error)

	// GetEnrollmentRequestByID retrieves an enrollment request by ID.
	GetEnrollmentRequestByID(ctx context.Context, id string) (*EnrollmentRequest, error)

	// ListEnrollmentRequests retrieves all enrollment requests.
	ListEnrollmentRequests(ctx context.Context) ([]EnrollmentRequest, error)

	// UpdateEnrollmentRequest updates status, resolved details, and stored Biscuit of a request.
	UpdateEnrollmentRequest(ctx context.Context, id string, status api.EnrollmentStatus, biscuit []byte, resolvedBy string) error

	// ListNodes retrieves all enrolled nodes.
	ListNodes(ctx context.Context) ([]EnrolledNode, error)

	// ListBootstrapTokens retrieves all bootstrap tokens.
	ListBootstrapTokens(ctx context.Context) ([]BootstrapToken, error)

	// Close closes the underlying database connection.
	Close() error
}
