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
)

// KeyPair holds cryptographic key information.
type KeyPair struct {
	Private    ed25519.PrivateKey
	Public     ed25519.PublicKey
	Expiration time.Time
}

// RouterLease represents a router registered with the control plane.
type RouterLease struct {
	PeerID      string
	Addresses   []string
	LastRenewal time.Time
	ExpiresAt   time.Time
}

// EnrolledNode represents a node enrolled in the mesh.
type EnrolledNode struct {
	PeerID         string
	PublicKey      []byte
	Biscuit        []byte
	Role           string
	EnrollmentType string
	ClaimsJSON     string
	EnrolledAt     time.Time
	ExpiresAt      time.Time
	Banned         bool
}

// BootstrapToken represents a pre-shared token for node enrollment.
type BootstrapToken struct {
	ID          string
	TokenHash   string
	Role        string
	MaxUsages   int
	UsagesCount int
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// EnrollmentRequest represents a pending or resolved node registration request (CSR).
type EnrollmentRequest struct {
	ID           string
	PeerID       string
	PublicKey    []byte
	TokenID      string
	Status       api.EnrollmentStatus
	BiscuitToken []byte
	CreatedAt    time.Time
	ResolvedAt   *time.Time
	ResolvedBy   string
}

// Store defines the persistent operations for the SAM control plane.
type Store interface {
	// GetCurrentKey retrieves the active key pair for biscuit signing.
	GetCurrentKey(ctx context.Context) (ed25519.PrivateKey, ed25519.PublicKey, error)

	// GetAllValidKeys retrieves the active key pair and any non-expired historical key pairs.
	GetAllValidKeys(ctx context.Context) ([]KeyPair, error)

	// RotateKeys rotates the current key to a new key pair and sets the expiration of the old key.
	RotateKeys(ctx context.Context, newPriv ed25519.PrivateKey, newPub ed25519.PublicKey, gracePeriod time.Duration) error

	// SaveInitialKey sets the initial key pair if no keys exist yet.
	SaveInitialKey(ctx context.Context, priv ed25519.PrivateKey, pub ed25519.PublicKey) error

	// EnrollNode registers or updates a node enrollment.
	EnrollNode(ctx context.Context, node *EnrolledNode) error

	// GetNode retrieves node enrollment details.
	GetNode(ctx context.Context, peerID string) (*EnrolledNode, error)

	// SetNodeBanned updates the banned status of a node.
	SetNodeBanned(ctx context.Context, peerID string, banned bool) error

	// IsNodeBanned checks if a node is currently banned.
	IsNodeBanned(ctx context.Context, peerID string) (bool, error)

	// UpsertRouterLease updates or creates a lease for a sam-router.
	UpsertRouterLease(ctx context.Context, lease *RouterLease) error

	// GetActiveRouters retrieves all routers whose leases are still valid.
	GetActiveRouters(ctx context.Context) ([]RouterLease, error)

	// SavePolicy persists the mesh configurations.
	SavePolicy(ctx context.Context, policy *api.PolicyConfig) error

	// GetPolicy loads the mesh configurations.
	GetPolicy(ctx context.Context) (*api.PolicyConfig, error)

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

	// Close closes the underlying database connection.
	Close() error
}
