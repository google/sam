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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

// generatePKCE generates a PKCE code verifier and challenge.
func generatePKCE() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

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
func (n *SamNode) InteractiveLogin(ctx context.Context, authURL, tokenURL, clientID, audience string) (string, error) {
	if authURL == "" {
		return "", fmt.Errorf("authorization URL is required")
	}
	if tokenURL == "" {
		return "", fmt.Errorf("token URL is required")
	}
	if clientID == "" {
		return "", fmt.Errorf("client ID is required")
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to start local server: %w", err)
	}
	defer func() { _ = listener.Close() }()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	authReq, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}
	q := authReq.URL.Query()
	q.Add("response_type", "code")
	q.Add("client_id", clientID)
	q.Add("redirect_uri", redirectURI)
	q.Add("scope", "openid email profile")
	q.Add("state", state)
	q.Add("code_challenge", challenge)
	q.Add("code_challenge_method", "S256")
	if audience != "" {
		q.Add("audience", audience)
	}
	authReq.URL.RawQuery = q.Encode()
	targetURL := authReq.URL.String()

	fmt.Println("------------------------------------------------------------")
	fmt.Println("OAuth Authorization Flow")
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("To authenticate, please go to the following URL in your browser:\n\n")
	fmt.Printf("  %s\n\n", targetURL)
	fmt.Println("Waiting for authorization...")
	fmt.Println("------------------------------------------------------------")

	// Try to open browser automatically
	openBrowserFunc(targetURL)

	codeChan := make(chan string)
	errChan := make(chan error)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("state") != state {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			select {
			case errChan <- fmt.Errorf("invalid state parameter received"):
			case <-ctx.Done():
			}
			return
		}
		if errStr := query.Get("error"); errStr != "" {
			desc := query.Get("error_description")
			http.Error(w, "Authorization failed: "+errStr, http.StatusBadRequest)
			select {
			case errChan <- fmt.Errorf("authorization failed: %s - %s", errStr, desc):
			case <-ctx.Done():
			}
			return
		}
		code := query.Get("code")
		if code == "" {
			http.Error(w, "No code in request", http.StatusBadRequest)
			select {
			case errChan <- fmt.Errorf("no code received"):
			case <-ctx.Done():
			}
			return
		}

		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Authorization successful!</h1><p>You can close this window and return to the CLI.</p></body></html>"))

		select {
		case codeChan <- code:
		case <-ctx.Done():
		}
	})

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("local server error: %w", err)
		}
	}()

	var code string
	select {
	case <-ctx.Done():
		_ = srv.Close()
		return "", ctx.Err()
	case err := <-errChan:
		_ = srv.Close()
		return "", err
	case code = <-codeChan:
		_ = srv.Close()
	}

	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", clientID)
	tokenData.Set("code", code)
	tokenData.Set("redirect_uri", redirectURI)
	tokenData.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
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
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("token request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IdToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	if tokenResp.IdToken != "" {
		return tokenResp.IdToken, nil
	}
	return tokenResp.AccessToken, nil
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

// DiscoverEndpoints discovers both token and authorization endpoints.
func (n *SamNode) DiscoverEndpoints(ctx context.Context, issuerURL string) (tokenURL, authURL string, err error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	var claims struct {
		TokenURL string `json:"token_endpoint"`
		AuthURL  string `json:"authorization_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return "", "", fmt.Errorf("failed to extract claims: %w", err)
	}
	return claims.TokenURL, claims.AuthURL, nil
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

var openBrowserFunc = openBrowser

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
