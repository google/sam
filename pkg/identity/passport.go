package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"sam/pkg/economy"
)

// PassportIssueRequest binds OIDC identity material to a peer and federation.
type PassportIssueRequest struct {
	PeerID       string
	FederationID string
	Subject      string
	Claims       map[string]string
}

// PassportClaims are extracted from a passport biscuit.
type PassportClaims struct {
	Token        string
	PeerID       string
	FederationID string
	Subject      string
	Claims       map[string]string
	IssuedAt     time.Time
	Issuer       string
}

const DefaultHubIssuer = "app.sam-mesh.dev"

var (
	hubKeyMu    sync.RWMutex
	hubKeyCache ed25519.PrivateKey
)

type signedPassportPayload struct {
	Issuer       string            `json:"issuer"`
	PeerID       string            `json:"peer_id"`
	FederationID string            `json:"federation_id"`
	MeshID       string            `json:"mesh_id"`
	Subject      string            `json:"subject"`
	Claims       map[string]string `json:"claims,omitempty"`
	IssuedAt     time.Time         `json:"issued_at"`
}

// SetHubSigningKey overrides the hub's signing key (for testing or secure key injection).
func SetHubSigningKey(priv ed25519.PrivateKey) {
	hubKeyMu.Lock()
	defer hubKeyMu.Unlock()
	hubKeyCache = priv
}

// hubSigningKey returns the hub's Ed25519 signing key.
// Priority: environment variable SAM_HUB_KEY (base64-encoded private key),
// then cached value, then deterministic seed (development default).
func hubSigningKey() ed25519.PrivateKey {
	hubKeyMu.RLock()
	if hubKeyCache != nil {
		defer hubKeyMu.RUnlock()
		return hubKeyCache
	}
	hubKeyMu.RUnlock()

	// Check environment variable for externally configured key
	if keyB64 := strings.TrimSpace(os.Getenv("SAM_HUB_KEY")); keyB64 != "" {
		if keyBytes, err := base64.RawURLEncoding.DecodeString(keyB64); err == nil && len(keyBytes) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(keyBytes)
			hubKeyMu.Lock()
			hubKeyCache = priv
			hubKeyMu.Unlock()
			return priv
		}
	}

	// Development default: deterministic seed
	seed := sha256.Sum256([]byte("sam-hub-root-key-v1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	hubKeyMu.Lock()
	hubKeyCache = priv
	hubKeyMu.Unlock()
	return priv
}

func HubPublicKeyBytes() []byte {
	pub := hubSigningKey().Public().(ed25519.PublicKey)
	out := make([]byte, len(pub))
	copy(out, pub)
	return out
}

func HubPublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(HubPublicKeyBytes())
}

// IssuePassportBiscuit issues a compact passport biscuit token.
// Token wire format keeps compatibility with SimpleBiscuitParser by placing
// identity binding data in the subject segment and caveats after ';'.
func IssuePassportBiscuit(_ context.Context, req PassportIssueRequest) (string, error) {
	req.PeerID = strings.TrimSpace(req.PeerID)
	req.FederationID = strings.TrimSpace(req.FederationID)
	req.Subject = strings.TrimSpace(req.Subject)
	if req.PeerID == "" || req.FederationID == "" || req.Subject == "" {
		return "", fmt.Errorf("peer_id, federation_id and subject are required")
	}
	if req.Claims == nil {
		req.Claims = map[string]string{}
	}
	payload := signedPassportPayload{
		Issuer:       DefaultHubIssuer,
		PeerID:       req.PeerID,
		FederationID: req.FederationID,
		MeshID:       req.FederationID,
		Subject:      req.Subject,
		Claims:       req.Claims,
		IssuedAt:     time.Now().UTC(),
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	sig := ed25519.Sign(hubSigningKey(), rawPayload)
	subject := fmt.Sprintf("passportv1|payload=%s|sig=%s",
		base64.RawURLEncoding.EncodeToString(rawPayload),
		base64.RawURLEncoding.EncodeToString(sig),
	)
	return subject + ";allow_skill=*", nil
}

func FetchPassportBiscuit(ctx context.Context, issueEndpoint string, accessToken string, req PassportIssueRequest) (string, error) {
	body, err := json.Marshal(map[string]string{
		"peer_id":    strings.TrimSpace(req.PeerID),
		"federation": strings.TrimSpace(req.FederationID),
		"mesh_id":    strings.TrimSpace(req.FederationID),
		"subject":    strings.TrimSpace(req.Subject),
		"email":      strings.TrimSpace(req.Claims["email"]),
	})
	if err != nil {
		return "", fmt.Errorf("marshal passport request: %w", err)
	}
	httpReq, err := newPostJSONRequest(ctx, strings.TrimSpace(issueEndpoint), body)
	if err != nil {
		return "", err
	}
	if token := strings.TrimSpace(accessToken); token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	respBody, err := doHTTPRequest(httpReq)
	if err != nil {
		return "", fmt.Errorf("requesting passport biscuit: %w", err)
	}
	var out struct {
		PassportBiscuit string `json:"passport_biscuit"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("parse passport response: %w", err)
	}
	if strings.TrimSpace(out.PassportBiscuit) == "" {
		return "", fmt.Errorf("passport_biscuit missing in response")
	}
	return strings.TrimSpace(out.PassportBiscuit), nil
}

func ValidatePassportBiscuit(ctx context.Context, token string, expectedPeerID string, expectedFederationID string) (*PassportClaims, error) {
	p, err := economy.SimpleBiscuitParser{}.Parse(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("parse passport biscuit: %w", err)
	}
	parts := strings.Split(p.Subject, "|")
	if len(parts) != 3 || parts[0] != "passportv1" {
		return nil, fmt.Errorf("invalid passport biscuit subject")
	}
	var rawPayload []byte
	var signature []byte
	for _, item := range parts[1:] {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], kv[1]
		switch key {
		case "payload":
			rawPayload, err = base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid passport payload encoding")
			}
		case "sig":
			signature, err = base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid passport signature encoding")
			}
		}
	}
	if len(rawPayload) == 0 || len(signature) == 0 {
		return nil, fmt.Errorf("invalid passport biscuit envelope")
	}
	if !ed25519.Verify(ed25519.PublicKey(HubPublicKeyBytes()), rawPayload, signature) {
		return nil, fmt.Errorf("passport signature verification failed")
	}
	var payload signedPassportPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("invalid passport payload")
	}
	claims := &PassportClaims{
		Token:        token,
		PeerID:       payload.PeerID,
		FederationID: payload.FederationID,
		Subject:      payload.Subject,
		Claims:       payload.Claims,
		IssuedAt:     payload.IssuedAt,
		Issuer:       payload.Issuer,
	}
	if strings.TrimSpace(claims.FederationID) == "" {
		claims.FederationID = strings.TrimSpace(payload.MeshID)
	}
	if claims.Claims == nil {
		claims.Claims = map[string]string{}
	}
	if strings.TrimSpace(expectedPeerID) != "" && claims.PeerID != strings.TrimSpace(expectedPeerID) {
		return nil, fmt.Errorf("passport peer mismatch")
	}
	if strings.TrimSpace(expectedFederationID) != "" && claims.FederationID != strings.TrimSpace(expectedFederationID) {
		return nil, fmt.Errorf("passport federation mismatch")
	}
	return claims, nil
}
