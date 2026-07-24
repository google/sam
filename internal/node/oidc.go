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

package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2/clientcredentials"
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
func (n *SamNode) InteractiveLogin(ctx context.Context, authURL, tokenURL, clientID, audience string, requestRefresh bool, headless bool) (string, error) {
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

	isHeadless := headless || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != ""

	var redirectURI string
	var listener net.Listener

	if isHeadless {
		redirectURI = "urn:ietf:wg:oauth:2.0:oob"
	} else {
		var err error
		// Try a few known ports to satisfy Dex which doesn't support RFC 8252 dynamic loopback
		// Since Dex strictly matches redirect URIs (Dex Issue #4836), we can't use `localhost:0`.
		// Instead, we try a small set of pre-registered fixed ports.
		for _, p := range []string{"13000", "13001", "13002"} {
			listener, err = net.Listen("tcp", "127.0.0.1:"+p)
			if err == nil {
				break
			}
		}
		if listener == nil {
			logger.Warn("Could not bind local OIDC listener (ports 13000-13002 busy). Falling back to headless (OOB) authorization.")
			isHeadless = true
			redirectURI = "urn:ietf:wg:oauth:2.0:oob"
		} else {
			defer func() { _ = listener.Close() }()
			port := listener.Addr().(*net.TCPAddr).Port
			redirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", port)
		}
	}

	authReq, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}
	q := authReq.URL.Query()
	q.Add("response_type", "code")
	q.Add("client_id", clientID)
	q.Add("redirect_uri", redirectURI)
	scope := "openid email profile"
	if requestRefresh {
		scope += " offline_access"
		q.Add("access_type", "offline")
		q.Add("prompt", "consent")
	}
	q.Add("scope", scope)
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
	if isHeadless {
		fmt.Println("After authorizing, paste the authorization code below:")
	} else {
		fmt.Println("Waiting for authorization... (If your browser fails, you can paste the callback URL or code here)")
	}
	fmt.Println("------------------------------------------------------------")

	// Try to open browser automatically
	openBrowserFunc(targetURL)

	loginCtx, loginCancel := context.WithCancel(ctx)
	defer loginCancel()

	codeChan := make(chan string)
	errChan := make(chan error)

	var srv *http.Server
	if !isHeadless {
		mux := http.NewServeMux()
		mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			if query.Get("state") != state {
				http.Error(w, "Invalid state parameter", http.StatusBadRequest)
				select {
				case errChan <- fmt.Errorf("invalid state parameter received"):
				case <-loginCtx.Done():
				}
				return
			}
			if errStr := query.Get("error"); errStr != "" {
				desc := query.Get("error_description")
				http.Error(w, "Authorization failed: "+errStr, http.StatusBadRequest)
				select {
				case errChan <- fmt.Errorf("authorization failed: %s - %s", errStr, desc):
				case <-loginCtx.Done():
				}
				return
			}
			code := query.Get("code")
			if code == "" {
				http.Error(w, "No code in request", http.StatusBadRequest)
				select {
				case errChan <- fmt.Errorf("no code received"):
				case <-loginCtx.Done():
				}
				return
			}

			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Authorization successful!</h1><p>You can close this window and return to the CLI.</p></body></html>"))

			select {
			case codeChan <- code:
			case <-loginCtx.Done():
			}
		})

		srv = &http.Server{Handler: mux}
		go func() {
			if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
				select {
				case errChan <- fmt.Errorf("local server error: %w", err):
				case <-loginCtx.Done():
				}
			}
		}()
	}

	// Also allow manual code entry via stdin
	go func() {
		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			return
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return
		}
		if parsed, err := url.Parse(input); err == nil && parsed.Query().Get("code") != "" {
			input = parsed.Query().Get("code")
		}
		select {
		case codeChan <- input:
		case <-loginCtx.Done():
		}
	}()

	shutdownSrv := func() {
		if srv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shutdownCtx)
			cancel()
		}
	}

	var code string
	select {
	case <-ctx.Done():
		shutdownSrv()
		return "", ctx.Err()
	case err := <-errChan:
		shutdownSrv()
		return "", err
	case code = <-codeChan:
		shutdownSrv()
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
		AccessToken  string `json:"access_token"`
		IdToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	if tokenResp.RefreshToken != "" && n.Store != nil {
		if err := n.Store.SaveRefreshToken(tokenResp.RefreshToken); err != nil {
			logger.Warnf("Failed to save refresh token: %v", err)
		}
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

// RefreshJWT refreshes the OIDC token using the stored refresh token.
func (n *SamNode) RefreshJWT(ctx context.Context, tokenURL, clientID, clientSecret, refreshToken string) (string, string, error) {
	tokenData := url.Values{}
	tokenData.Set("grant_type", "refresh_token")
	tokenData.Set("client_id", clientID)
	tokenData.Set("refresh_token", refreshToken)
	if clientSecret != "" {
		tokenData.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
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
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error != "" {
			return "", "", fmt.Errorf("refresh token request failed (status %s): %s - %s", resp.Status, errResp.Error, errResp.ErrorDescription)
		}
		return "", "", fmt.Errorf("refresh token request failed with status: %s", resp.Status)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IdToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", "", err
	}

	jwtStr := tokenResp.AccessToken
	if tokenResp.IdToken != "" {
		jwtStr = tokenResp.IdToken
	}
	if jwtStr == "" {
		return "", "", fmt.Errorf("token response did not contain an access_token or id_token")
	}
	return jwtStr, tokenResp.RefreshToken, nil
}
