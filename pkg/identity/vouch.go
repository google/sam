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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	internaldb "sam/internal/db"
)

// Vouch is the portable credential that the Hub issues after a successful
// Device Authorization Grant. It binds the authenticated user's OIDC claims
// to a specific libp2p PeerID and is signed by the Hub's Ed25519 key so that
// any peer in the mesh can verify it offline.
type Vouch struct {
	// PeerID is the libp2p peer identity this credential is bound to.
	PeerID string `json:"peer_id"`
	// Issuer is the Hub base URL that issued this credential.
	Issuer string `json:"issuer"`
	// Subject is the OIDC subject (stable user identifier).
	Subject string `json:"subject,omitempty"`
	// Claims contains the OIDC profile claims forwarded by the Hub.
	// Standard keys: "email", "name", "org", "picture".
	Claims map[string]string `json:"claims,omitempty"`
	// IssuedAt records when the Hub minted this Vouch.
	IssuedAt time.Time `json:"issued_at"`
	// Expiry is when this Vouch should stop being trusted.
	Expiry time.Time `json:"expiry"`
	// Algorithm is the signature algorithm, always "libp2p-ed25519".
	Algorithm string `json:"alg"`
	// Signature is the base64url-encoded Ed25519 signature over the canonical
	// payload (all fields except Signature, JSON-marshaled sorted-key).
	Signature string `json:"signature"`
}

// IsExpired reports whether the Vouch has passed its expiry time.
func (v *Vouch) IsExpired() bool {
	return !v.Expiry.IsZero() && time.Now().After(v.Expiry)
}

// Email is a convenience accessor for the "email" claim.
func (v *Vouch) Email() string { return v.Claims["email"] }

// Name is a convenience accessor for the "name" claim.
func (v *Vouch) Name() string { return v.Claims["name"] }

// Org is a convenience accessor for the "org" claim.
func (v *Vouch) Org() string { return v.Claims["org"] }

// vouchPayload is the subset of Vouch that is covered by the Hub signature.
// The Signature field is intentionally excluded.
type vouchPayload struct {
	PeerID    string            `json:"peer_id"`
	Issuer    string            `json:"issuer"`
	Subject   string            `json:"subject,omitempty"`
	Claims    map[string]string `json:"claims,omitempty"`
	IssuedAt  time.Time         `json:"issued_at"`
	Expiry    time.Time         `json:"expiry"`
	Algorithm string            `json:"alg"`
}

// vouchSigPayload returns the canonical bytes the Hub signs.
func vouchSigPayload(v *Vouch) ([]byte, error) {
	p := vouchPayload{
		PeerID:    v.PeerID,
		Issuer:    v.Issuer,
		Subject:   v.Subject,
		Claims:    v.Claims,
		IssuedAt:  v.IssuedAt,
		Expiry:    v.Expiry,
		Algorithm: v.Algorithm,
	}
	return json.Marshal(p)
}

// SignVouch signs a Vouch with hubKey and sets Vouch.Signature.
// Intended for use by a Hub implementation; clients call VerifyVouch.
func SignVouch(v *Vouch, hubKey ed25519.PrivateKey) error {
	v.Algorithm = "libp2p-ed25519"
	payload, err := vouchSigPayload(v)
	if err != nil {
		return fmt.Errorf("marshaling vouch payload: %w", err)
	}
	sig := ed25519.Sign(hubKey, payload)
	v.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

// VerifyVouch verifies the Hub signature on a Vouch and checks expiry.
func VerifyVouch(v *Vouch, hubPubKey ed25519.PublicKey) error {
	if v == nil {
		return errors.New("vouch is nil")
	}
	if v.Algorithm != "libp2p-ed25519" {
		return fmt.Errorf("unsupported vouch algorithm %q", v.Algorithm)
	}
	if v.IsExpired() {
		return fmt.Errorf("vouch expired at %s", v.Expiry.Format(time.RFC3339))
	}

	payload, err := vouchSigPayload(v)
	if err != nil {
		return fmt.Errorf("marshaling vouch payload for verification: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(v.Signature)
	if err != nil {
		return fmt.Errorf("decoding vouch signature: %w", err)
	}
	if !ed25519.Verify(hubPubKey, payload, sig) {
		return errors.New("vouch signature verification failed")
	}
	return nil
}

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
	// Vouch is the Hub-signed credential bound to the local PeerID.
	Vouch *Vouch `json:"vouch,omitempty"`
}

const (
	credentialsBucketKey      = "local"
	legacyVouchBucketFallback = "default"
	credentialsCurrentVersion = 2
	vouchCurrentVersion       = 1
)

type credentialsRecord struct {
	PeerID       string    `json:"peer_id,omitempty"`
	HubURL       string    `json:"hub_url"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenExpiry  time.Time `json:"token_expiry,omitempty"`
}

type vouchRecord struct {
	Vouch *Vouch `json:"vouch,omitempty"`
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
		PeerID:       rec.PeerID,
		HubURL:       rec.HubURL,
		AccessToken:  rec.AccessToken,
		RefreshToken: rec.RefreshToken,
		TokenExpiry:  rec.TokenExpiry,
	}

	if creds.PeerID != "" {
		v, vErr := s.loadVouch(creds.PeerID)
		if vErr == nil {
			creds.Vouch = v
		}
	}
	if creds.Vouch == nil {
		v, vErr := s.loadVouch(legacyVouchBucketFallback)
		if vErr == nil {
			creds.Vouch = v
		}
	}
	if creds.PeerID == "" && creds.Vouch != nil {
		creds.PeerID = creds.Vouch.PeerID
	}
	return creds, nil
}

// Save writes creds to the identities and vouches buckets.
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
	}
	if rec.PeerID == "" && creds.Vouch != nil {
		rec.PeerID = strings.TrimSpace(creds.Vouch.PeerID)
	}

	encodedRec, err := s.codec.Marshal(credentialsCurrentVersion, rec)
	if err != nil {
		return fmt.Errorf("encoding identity record: %w", err)
	}
	if err := s.store.Put(context.Background(), internaldb.BucketIdentities, credentialsBucketKey, encodedRec); err != nil {
		return fmt.Errorf("writing identity record: %w", err)
	}
	if creds.Vouch != nil {
		vkey := strings.TrimSpace(creds.Vouch.PeerID)
		if vkey == "" {
			vkey = legacyVouchBucketFallback
		}
		rec := vouchRecord{Vouch: creds.Vouch}
		encodedVouch, err := s.codec.Marshal(vouchCurrentVersion, rec)
		if err != nil {
			return fmt.Errorf("encoding vouch record: %w", err)
		}
		if err := s.store.Put(context.Background(), internaldb.BucketVouches, vkey, encodedVouch); err != nil {
			return fmt.Errorf("writing vouch record: %w", err)
		}
	}
	return nil
}

func (s *CredentialStore) loadVouch(key string) (*Vouch, error) {
	data, err := s.store.Get(context.Background(), internaldb.BucketVouches, key)
	if err != nil {
		return nil, err
	}
	var rec vouchRecord
	if err := s.codec.Unmarshal(data, vouchCurrentVersion, &rec, nil); err != nil {
		return nil, err
	}
	if rec.Vouch == nil {
		return nil, os.ErrNotExist
	}
	return rec.Vouch, nil
}

// Clear removes stored credentials and the current vouch key if present.
func (s *CredentialStore) Clear() error {
	creds, _ := s.Load()
	if err := s.store.Delete(context.Background(), internaldb.BucketIdentities, credentialsBucketKey); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing identity record: %w", err)
	}
	if creds != nil {
		if pid := strings.TrimSpace(creds.PeerID); pid != "" {
			_ = s.store.Delete(context.Background(), internaldb.BucketVouches, pid)
		}
	}
	_ = s.store.Delete(context.Background(), internaldb.BucketVouches, legacyVouchBucketFallback)
	return nil
}

// NewVouch creates an unsigned Vouch that a Hub can then sign with SignVouch.
// peerID must be the hex/base58 string form of the peer identity.
// claims is typically the OIDC userinfo response subset: email, name, org, …
func NewVouch(peerID, issuer, subject string, claims map[string]string, ttl time.Duration) *Vouch {
	now := time.Now().UTC()
	return &Vouch{
		PeerID:   peerID,
		Issuer:   issuer,
		Subject:  subject,
		Claims:   claims,
		IssuedAt: now,
		Expiry:   now.Add(ttl),
	}
}

// SelfSignVouch creates a self-attested Vouch signed with the local peer key.
// This is used when no Hub is available and the node wants to advertise minimal
// identity in its AgentCard.
func SelfSignVouch(peerID string, privKey ed25519.PrivateKey) (*Vouch, error) {
	if peerID == "" {
		return nil, errors.New("peer ID must not be empty")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key length")
	}
	// Use a random nonce as subject so self-signed vouches are unlinkable.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating self-vouch nonce: %w", err)
	}
	subject := "self:" + base64.RawURLEncoding.EncodeToString(nonce)
	v := &Vouch{
		PeerID:   peerID,
		Issuer:   "self",
		Subject:  subject,
		Claims:   map[string]string{},
		IssuedAt: time.Now().UTC(),
		Expiry:   time.Now().UTC().Add(24 * time.Hour),
	}
	pubKey := privKey.Public().(ed25519.PublicKey)
	if err := SignVouch(v, privKey); err != nil {
		return nil, err
	}
	// Embed the public key as a claim so verifiers can reconstruct trust.
	v.Claims["pub_key"] = base64.RawURLEncoding.EncodeToString(pubKey)
	return v, nil
}

// HubDiscoveryDoc is the subset of OIDC provider metadata that SAM needs.
type HubDiscoveryDoc struct {
	Issuer             string `json:"issuer"`
	DeviceAuthEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint      string `json:"token_endpoint"`
	UserinfoEndpoint   string `json:"userinfo_endpoint,omitempty"`
	VouchEndpoint      string `json:"vouch_endpoint,omitempty"` // SAM extension
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
