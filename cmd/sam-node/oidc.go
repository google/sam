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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/sam/api"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/protobuf/proto"
)

// FetchJWT fetches a JWT token using the Client Credentials flow.
func (n *SamNode) FetchJWT(ctx context.Context, tokenURL, clientID, clientSecret string) (string, error) {
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}
	token, err := config.Token(ctx)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// InteractiveLogin prompts the user to go to a URL and enter a code.
func (n *SamNode) InteractiveLogin(ctx context.Context, deviceAuthURL, tokenURL, clientID, audience string) (string, error) {
	if deviceAuthURL == "" {
		return "", fmt.Errorf("device authorization URL is required")
	}
	if tokenURL == "" {
		return "", fmt.Errorf("token URL is required")
	}
	if clientID == "" {
		return "", fmt.Errorf("client ID is required for device flow")
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "openid email profile")
	if audience != "" {
		data.Set("audience", audience)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", deviceAuthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		return "", fmt.Errorf("device auth request failed: %s - %s", resp.Status, string(body))
	}

	var authResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", err
	}

	fmt.Println("------------------------------------------------------------")
	fmt.Println("Device Authorization Flow")
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("To authenticate, please go to the following URL in your browser:\n\n")
	targetURL := authResp.VerificationURIComplete
	if targetURL == "" {
		targetURL = authResp.VerificationURI
	}
	fmt.Printf("  %s\n\n", targetURL)
	if authResp.VerificationURIComplete == "" {
		fmt.Printf("And enter the following code:\n\n")
		fmt.Printf("  %s\n\n", authResp.UserCode)
	} else {
		fmt.Println("The login code has been pre-filled for your convenience.")
	}
	fmt.Println("Waiting for authorization...")
	fmt.Println("------------------------------------------------------------")

	// Try to open browser automatically
	openBrowser(targetURL)

	interval := authResp.Interval
	if interval <= 0 {
		interval = 5
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			pollData := url.Values{}
			pollData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			pollData.Set("device_code", authResp.DeviceCode)
			pollData.Set("client_id", clientID)

			req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(pollData.Encode()))
			if err != nil {
				return "", err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				return "", err
			}

			if resp.StatusCode == http.StatusOK {
				var tokenResp struct {
					AccessToken string `json:"access_token"`
					IdToken     string `json:"id_token"`
				}
				err := json.NewDecoder(resp.Body).Decode(&tokenResp)
				if closeErr := resp.Body.Close(); closeErr != nil {
					logger.Errorf("Failed to close response body: %v", closeErr)
				}
				if err != nil {
					return "", err
				}
				if tokenResp.IdToken != "" {
					return tokenResp.IdToken, nil
				}
				return tokenResp.AccessToken, nil
			}

			var errResp struct {
				Error string `json:"error"`
			}
			err = json.NewDecoder(resp.Body).Decode(&errResp)
			if closeErr := resp.Body.Close(); closeErr != nil {
				logger.Errorf("Failed to close response body: %v", closeErr)
			}
			if err != nil {
				return "", fmt.Errorf("token request failed with status %s", resp.Status)
			}

			switch errResp.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				ticker.Reset(time.Duration(interval+5) * time.Second)
				continue
			case "expired_token":
				return "", fmt.Errorf("device code expired")
			case "access_denied":
				return "", fmt.Errorf("access denied by user")
			default:
				return "", fmt.Errorf("token request failed: %s", errResp.Error)
			}
		}
	}
}

// DiscoverTokenURL discovers the token URL from the OIDC issuer.
func (n *SamNode) DiscoverTokenURL(ctx context.Context, issuerURL string) (string, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	var claims struct {
		TokenURL string `json:"token_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return "", fmt.Errorf("failed to extract claims: %w", err)
	}
	if claims.TokenURL == "" {
		return "", fmt.Errorf("token_endpoint not found in discovery document")
	}
	return claims.TokenURL, nil
}

// DiscoverEndpoints discovers both token and device auth endpoints.
func (n *SamNode) DiscoverEndpoints(ctx context.Context, issuerURL string) (tokenURL, deviceURL string, err error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	var claims struct {
		TokenURL  string `json:"token_endpoint"`
		DeviceURL string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return "", "", fmt.Errorf("failed to extract claims: %w", err)
	}
	return claims.TokenURL, claims.DeviceURL, nil
}

// DiscoverHubInfo queries the hub's /info endpoint to fetch OIDC configurations.
func (n *SamNode) DiscoverHubInfo(ctx context.Context, hubURL string) (*api.HubInfoResponse, error) {
	if !strings.HasPrefix(hubURL, "http://") && !strings.HasPrefix(hubURL, "https://") {
		hubURL = "https://" + hubURL
	}
	hubURL = strings.TrimSuffix(hubURL, "/")

	urlStr := hubURL + "/info"
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		return nil, fmt.Errorf("hub returned status %s: %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var hubInfo api.HubInfoResponse
	if err := proto.Unmarshal(body, &hubInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hub info: %w", err)
	}

	return &hubInfo, nil
}

func openBrowser(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		logger.Debugf("Failed to open browser: invalid or unsafe URL scheme %q", targetURL)
		return
	}
	var cmdErr error
	switch runtime.GOOS {
	case "linux":
		cmdErr = exec.Command("xdg-open", targetURL).Start()
	case "darwin":
		cmdErr = exec.Command("open", targetURL).Start()
	case "windows":
		cmdErr = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
	default:
		cmdErr = fmt.Errorf("unsupported platform")
	}
	if cmdErr != nil {
		logger.Debugf("Failed to open browser: %v", cmdErr)
	}
}
