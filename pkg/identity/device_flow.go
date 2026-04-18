package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultDevicePollInterval is how often the client polls the token endpoint.
	DefaultDevicePollInterval = 5 * time.Second
	// DefaultDeviceGrantType is the OAuth2 Device Authorization Grant type.
	DefaultDeviceGrantType = "urn:ietf:params:oauth2:grant-type:device_code"
)

// DeviceAuthResponse is the response from the Device Authorization endpoint.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse is the OAuth2 token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	// OAuth2 error fields.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// DeviceFlowConfig holds the parameters for the Device Authorization Grant.
type DeviceFlowConfig struct {
	// ClientID is the OAuth2 client ID registered with the Hub.
	ClientID string
	// Scopes requested from the Hub. Defaults to ["openid", "profile", "email"].
	Scopes []string
	// PollInterval overrides the server-suggested polling interval.
	PollInterval time.Duration
	// HTTPClient allows injecting a custom client (useful in tests).
	HTTPClient *http.Client
}

// DeviceFlowResult is the outcome of a successful Device Authorization Grant.
type DeviceFlowResult struct {
	AccessToken  string
	RefreshToken string
	TokenExpiry  time.Time
	IDToken      string
}

// StartDeviceFlow initiates a Device Authorization Grant against the Hub.
// It returns a DeviceAuthResponse that the caller must present to the user
// (VerificationURI + UserCode).
func StartDeviceFlow(ctx context.Context, deviceEndpoint string, cfg DeviceFlowConfig) (*DeviceAuthResponse, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	form := url.Values{}
	form.Set("client_id", cfg.ClientID)
	form.Set("scope", strings.Join(scopes, " "))

	body, err := postForm(ctx, deviceEndpoint, form, cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("device authorization request: %w", err)
	}

	var resp DeviceAuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing device authorization response: %w", err)
	}
	if resp.DeviceCode == "" {
		return nil, fmt.Errorf("hub did not return a device_code")
	}
	return &resp, nil
}

// PollDeviceToken polls the token endpoint until the user completes the Device
// Authorization flow, the device code expires, or ctx is cancelled.
//
// Returns ErrDeviceAuthPending while waiting for the user, ErrDeviceAuthSlowDown
// if the Hub requests a longer polling interval, and ErrDeviceAuthExpired if the
// code has expired.
func PollDeviceToken(ctx context.Context, tokenEndpoint string, auth *DeviceAuthResponse, cfg DeviceFlowConfig) (*DeviceFlowResult, error) {
	interval := cfg.PollInterval
	if interval == 0 {
		if auth.Interval > 0 {
			interval = time.Duration(auth.Interval) * time.Second
		} else {
			interval = DefaultDevicePollInterval
		}
	}

	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}

		if time.Now().After(deadline) {
			return nil, ErrDeviceAuthExpired
		}

		result, pending, err := exchangeDeviceCode(ctx, tokenEndpoint, auth.DeviceCode, cfg)
		if err != nil {
			return nil, err
		}
		if pending {
			continue
		}
		if result != nil {
			return result, nil
		}
	}
}

// exchangeDeviceCode does one polling request to the token endpoint.
// Returns (result, false, nil) on success, (nil, true, nil) when still pending,
// and (nil, false, err) on a terminal error.
func exchangeDeviceCode(ctx context.Context, tokenEndpoint, deviceCode string, cfg DeviceFlowConfig) (*DeviceFlowResult, bool, error) {
	form := url.Values{}
	form.Set("grant_type", DefaultDeviceGrantType)
	form.Set("device_code", deviceCode)
	form.Set("client_id", cfg.ClientID)

	body, err := postForm(ctx, tokenEndpoint, form, cfg.HTTPClient)
	if err != nil {
		return nil, false, fmt.Errorf("token exchange request: %w", err)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, false, fmt.Errorf("parsing token response: %w", err)
	}

	switch tr.Error {
	case "":
		// Success.
	case "authorization_pending":
		return nil, true, nil
	case "slow_down":
		return nil, true, nil // caller will retry on next tick
	case "expired_token", "access_denied":
		return nil, false, ErrDeviceAuthExpired
	default:
		return nil, false, fmt.Errorf("token error %q: %s", tr.Error, tr.ErrorDescription)
	}

	if tr.AccessToken == "" {
		return nil, false, fmt.Errorf("token endpoint returned no access_token")
	}

	expiry := time.Time{}
	if tr.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	return &DeviceFlowResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenExpiry:  expiry,
		IDToken:      tr.IDToken,
	}, false, nil
}

// FetchVouch calls the Hub's vouch endpoint to obtain a signed Vouch in
// exchange for a valid access token and the local PeerID.
//
// The Hub is expected to accept a JSON body of the form:
//
//	{"peer_id": "<peerID>"}
//
// and return a signed Vouch JSON object.
func FetchVouch(ctx context.Context, vouchEndpoint, accessToken, peerID string, httpClient *http.Client) (*Vouch, error) {
	payload, err := json.Marshal(map[string]string{"peer_id": peerID})
	if err != nil {
		return nil, fmt.Errorf("marshaling vouch request: %w", err)
	}

	req, err := newPostJSONRequest(ctx, vouchEndpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vouch request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading vouch response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vouch endpoint returned %s: %s", resp.Status, body)
	}

	var v Vouch
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("parsing vouch response: %w", err)
	}
	return &v, nil
}

// Device flow sentinel errors.
var (
	ErrDeviceAuthPending  = fmt.Errorf("device authorization pending")
	ErrDeviceAuthSlowDown = fmt.Errorf("device authorization: slow down")
	ErrDeviceAuthExpired  = fmt.Errorf("device authorization code expired or denied")
)

// ---------------------------------------------------------------------------
// Internal HTTP helpers
// ---------------------------------------------------------------------------

func postForm(ctx context.Context, endpoint string, form url.Values, client *http.Client) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<16))
}

func newGetRequest(ctx context.Context, u string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("building GET request for %s: %w", u, err)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func newPostJSONRequest(ctx context.Context, u string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("building POST request for %s: %w", u, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func doHTTPRequest(req *http.Request) ([]byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %s: %s", resp.Status, body)
	}
	return body, nil
}
