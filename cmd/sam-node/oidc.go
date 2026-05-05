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
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
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
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("device auth request failed: %s - %s", resp.Status, string(body))
	}

	var authResp struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", err
	}

	fmt.Println("------------------------------------------------------------")
	fmt.Println("Device Authorization Flow")
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("To authenticate, please go to the following URL in your browser:\n\n")
	fmt.Printf("  %s\n\n", authResp.VerificationURI)
	fmt.Printf("And enter the following code:\n\n")
	fmt.Printf("  %s\n\n", authResp.UserCode)
	fmt.Println("Waiting for authorization...")
	fmt.Println("------------------------------------------------------------")

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
