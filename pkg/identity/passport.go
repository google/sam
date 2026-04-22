package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	rawClaims, err := json.Marshal(req.Claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	subject := fmt.Sprintf("passport|sub=%s|peer=%s|fed=%s|claims=%s", sanitize(req.Subject), sanitize(req.PeerID), sanitize(req.FederationID), sanitize(string(rawClaims)))
	return subject + ";allow_skill=*", nil
}

func FetchPassportBiscuit(ctx context.Context, issueEndpoint string, accessToken string, req PassportIssueRequest) (string, error) {
	body, err := json.Marshal(map[string]string{
		"peer_id":    strings.TrimSpace(req.PeerID),
		"federation": strings.TrimSpace(req.FederationID),
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
	if len(parts) < 5 || parts[0] != "passport" {
		return nil, fmt.Errorf("invalid passport biscuit subject")
	}
	claims := &PassportClaims{Token: token, Claims: map[string]string{}}
	for _, item := range parts[1:] {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], unsanitize(kv[1])
		switch key {
		case "sub":
			claims.Subject = value
		case "peer":
			claims.PeerID = value
		case "fed":
			claims.FederationID = value
		case "claims":
			_ = json.Unmarshal([]byte(value), &claims.Claims)
		}
	}
	if strings.TrimSpace(expectedPeerID) != "" && claims.PeerID != strings.TrimSpace(expectedPeerID) {
		return nil, fmt.Errorf("passport peer mismatch")
	}
	if strings.TrimSpace(expectedFederationID) != "" && claims.FederationID != strings.TrimSpace(expectedFederationID) {
		return nil, fmt.Errorf("passport federation mismatch")
	}
	return claims, nil
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "|", "%7C")
	s = strings.ReplaceAll(s, ";", "%3B")
	s = strings.ReplaceAll(s, "=", "%3D")
	return s
}

func unsanitize(s string) string {
	s = strings.ReplaceAll(s, "%7C", "|")
	s = strings.ReplaceAll(s, "%3B", ";")
	s = strings.ReplaceAll(s, "%3D", "=")
	return s
}
