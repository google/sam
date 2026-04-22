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

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	internaldb "sam/internal/db"
)

// StoredCredentials is the persisted identity state in the SAM key-value store.
type StoredCredentials struct {
	PeerID string `json:"peer_id,omitempty"`
	// HubURL is the hub the user authenticated against.
	HubURL string `json:"hub_url"`
	// AccessToken is the OAuth2 access token returned by the Hub.
	AccessToken string `json:"access_token"`
	// RefreshToken allows silent token refresh.
	RefreshToken string `json:"refresh_token,omitempty"`
	// TokenExpiry is when the access token expires.
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
	// PassportBiscuit is the hub-issued biscuit binding identity to peer/federation.
	PassportBiscuit string `json:"passport_biscuit,omitempty"`
}

const (
	credentialsBucketKey      = "local"
	credentialsCurrentVersion = 2
)

type credentialsRecord struct {
	PeerID       string    `json:"peer_id,omitempty"`
	HubURL       string    `json:"hub_url"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenExpiry  time.Time `json:"token_expiry,omitempty"`
	Passport     string    `json:"passport_biscuit,omitempty"`
}

// CredentialStore reads and writes SAM credentials from the local state DB.
type CredentialStore struct {
	path  string
	store internaldb.Store
	codec internaldb.Codec
}

// DefaultCredentialStore returns a store that uses ~/.config/sam/state.db.
func DefaultCredentialStore() (*CredentialStore, error) {
	path, err := internaldb.DefaultStatePath()
	if err != nil {
		return nil, err
	}
	return NewCredentialStore(path)
}

// NewCredentialStore creates a store backed by the given bbolt file path.
func NewCredentialStore(path string) (*CredentialStore, error) {
	if path == "" {
		return nil, errors.New("credential store path must not be empty")
	}
	store, err := internaldb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening state store: %w", err)
	}
	return &CredentialStore{path: path, store: store, codec: internaldb.JSONCodec{}}, nil
}

// Path returns the resolved path to the state DB file.
func (s *CredentialStore) Path() string { return s.path }

// Close releases store resources.
func (s *CredentialStore) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Close()
}

// Load reads stored credentials. Returns nil, nil when no identity exists.
func (s *CredentialStore) Load() (*StoredCredentials, error) {
	data, err := s.store.Get(context.Background(), internaldb.BucketIdentities, credentialsBucketKey)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading identity record: %w", err)
	}

	var rec credentialsRecord
	if err := s.codec.Unmarshal(data, credentialsCurrentVersion, &rec, func(payload map[string]any, fromVersion int) map[string]any {
		if fromVersion < 2 {
			if _, ok := payload["peer_id"]; !ok {
				payload["peer_id"] = ""
			}
		}
		return payload
	}); err != nil {
		return nil, fmt.Errorf("decoding identity record: %w", err)
	}

	creds := &StoredCredentials{
		PeerID:          rec.PeerID,
		HubURL:          rec.HubURL,
		AccessToken:     rec.AccessToken,
		RefreshToken:    rec.RefreshToken,
		TokenExpiry:     rec.TokenExpiry,
		PassportBiscuit: rec.Passport,
	}
	return creds, nil
}

// Save writes creds to the identities bucket.
func (s *CredentialStore) Save(creds *StoredCredentials) error {
	if creds == nil {
		return errors.New("cannot save nil credentials")
	}
	rec := credentialsRecord{
		PeerID:       strings.TrimSpace(creds.PeerID),
		HubURL:       creds.HubURL,
		AccessToken:  creds.AccessToken,
		RefreshToken: creds.RefreshToken,
		TokenExpiry:  creds.TokenExpiry,
		Passport:     strings.TrimSpace(creds.PassportBiscuit),
	}

	encodedRec, err := s.codec.Marshal(credentialsCurrentVersion, rec)
	if err != nil {
		return fmt.Errorf("encoding identity record: %w", err)
	}
	if err := s.store.Put(context.Background(), internaldb.BucketIdentities, credentialsBucketKey, encodedRec); err != nil {
		return fmt.Errorf("writing identity record: %w", err)
	}
	return nil
}

// Clear removes stored credentials.
func (s *CredentialStore) Clear() error {
	if err := s.store.Delete(context.Background(), internaldb.BucketIdentities, credentialsBucketKey); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing identity record: %w", err)
	}
	return nil
}

// HubDiscoveryDoc is the subset of OIDC provider metadata that SAM needs.
type HubDiscoveryDoc struct {
	Issuer             string `json:"issuer"`
	DeviceAuthEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint      string `json:"token_endpoint"`
	UserinfoEndpoint   string `json:"userinfo_endpoint,omitempty"`
	JWKsURI            string `json:"jwks_uri,omitempty"`
}

// FetchHubDiscovery retrieves the OIDC discovery document from hubURL.
// hubURL should be the base URL of the Hub (e.g. "https://hub.example.com").
// The document is fetched from <hubURL>/.well-known/openid-configuration.
func FetchHubDiscovery(ctx context.Context, hubURL string) (*HubDiscoveryDoc, error) {
	discoveryURL := strings.TrimRight(hubURL, "/") + "/.well-known/openid-configuration"
	req, err := newGetRequest(ctx, discoveryURL)
	if err != nil {
		return nil, err
	}
	body, err := doHTTPRequest(req)
	if err != nil {
		return nil, fmt.Errorf("fetching hub discovery doc from %s: %w", discoveryURL, err)
	}
	var doc HubDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parsing hub discovery doc: %w", err)
	}
	if doc.DeviceAuthEndpoint == "" {
		return nil, fmt.Errorf("hub at %s does not advertise device_authorization_endpoint", hubURL)
	}
	return &doc, nil
}
