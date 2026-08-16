package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/sam/api"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
)

type Config struct {
	ControlPlaneURL string
	AdminToken      string
	StaticDir       string
	BasePath        string
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	provider *oidc.Provider
	clientID string
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.ControlPlaneURL == "" {
		return nil, fmt.Errorf("ControlPlaneURL is required")
	}

	controlPlaneURL, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ControlPlaneURL: %w", err)
	}

	var provider *oidc.Provider
	var clientID string

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(cfg.ControlPlaneURL + "/info")
	if err != nil {
		return nil, fmt.Errorf("failed to query control-plane info for OIDC discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read control-plane info body: %w", err)
		}
		var info api.ControlPlaneInfoResponse
		if err := proto.Unmarshal(body, &info); err != nil {
			return nil, fmt.Errorf("failed to unmarshal control plane info: %w", err)
		}

		if info.OidcIssuer != "" && info.ClientId != "" {
			// Bound the discovery client so an unresponsive issuer can't hang startup.
			oidcClient := &http.Client{Timeout: 10 * time.Second}
			discoveryCtx := oidc.ClientContext(context.Background(), oidcClient)
			provider, err = discoverProviderWithRetry(discoveryCtx, info.OidcIssuer, oidcDiscoveryMaxAttempts, oidcDiscoveryBaseDelay, oidcDiscoveryMaxDelay)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed OIDC discovery on %s: %v\n", info.OidcIssuer, err)
			} else if provider.Endpoint().AuthURL != "" && provider.Endpoint().TokenURL != "" {
				clientID = info.ClientId
			} else {
				fmt.Fprintf(os.Stderr, "Info: discovered issuer %s does not support authorization flow (M2M only)\n", info.OidcIssuer)
				provider = nil // Disable console interactive endpoints
			}
		}
	}

	s := &Server{
		cfg:      cfg,
		mux:      http.NewServeMux(),
		provider: provider,
		clientID: clientID,
	}
	// Create reverse proxy to the control plane
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(controlPlaneURL)
			r.Out.Host = r.In.Host
			// If Authorization header is not set, inject from sam_session cookie
			if r.Out.Header.Get("Authorization") == "" {
				if cookie, err := r.In.Cookie("sam_session"); err == nil && cookie.Value != "" {
					r.Out.Header.Set("Authorization", "Bearer "+cookie.Value)
				}
			}
		},
	}

	routes := http.NewServeMux()

	// Proxy all API requests to the control plane
	routes.Handle("/api/", http.StripPrefix("/api", proxy))

	// Serve static files
	fs := http.FileServer(http.Dir(s.cfg.StaticDir))
	routes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Basic check if file exists
		path := filepath.Join(s.cfg.StaticDir, r.URL.Path)
		if _, err := os.Stat(path); os.IsNotExist(err) && r.URL.Path != "/" {
			// SPA fallback: return index.html for unknown paths (useful for flutter/react router)
			http.ServeFile(w, r, filepath.Join(s.cfg.StaticDir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})

	// OIDC login endpoints
	if s.provider != nil {
		routes.HandleFunc("/auth/login", s.HandleLogin)
		routes.HandleFunc("/auth/callback", s.HandleCallback)
		routes.HandleFunc("/auth/session", s.HandleSession)
	}
	routes.HandleFunc("/auth/logout", s.HandleLogout)
	routes.HandleFunc("/info", s.HandleInfo)

	// Serve under BasePath too, so the links this server emits resolve without the proxy
	// stripping the prefix. Still served at the root for proxies that do strip it.
	if s.cfg.BasePath != "" {
		s.mux.Handle(s.cfg.BasePath+"/", http.StripPrefix(s.cfg.BasePath, routes))
	}
	s.mux.Handle("/", routes)

	return s, nil
}

// Defaults for discoverProviderWithRetry; matches sam-control-plane's
// discoverProviders so a transient hiccup during rollout (e.g. Dex still
// starting up) doesn't permanently disable console OIDC login, since the
// console's /info reports healthy either way and Kubernetes won't restart it.
const (
	oidcDiscoveryMaxAttempts = 5
	oidcDiscoveryBaseDelay   = 1 * time.Second
	oidcDiscoveryMaxDelay    = 8 * time.Second
)

// discoverProviderWithRetry retries OIDC discovery with exponential backoff so a
// transient upstream hiccup (e.g. the identity provider mid-rollout) doesn't
// permanently disable the console's OIDC login endpoints.
func discoverProviderWithRetry(ctx context.Context, issuer string, maxAttempts int, baseDelay, maxDelay time.Duration) (*oidc.Provider, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > maxDelay {
				delay = maxDelay
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		provider, err := oidc.NewProvider(ctx, issuer)
		if err == nil {
			return provider, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "Warning: OIDC discovery attempt %d/%d for %s failed: %v\n", attempt+1, maxAttempts, issuer, err)
	}
	return nil, lastErr
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "sam_session",
		Value:  "",
		Path:   s.cfg.BasePath + "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s%s/auth/callback", scheme, r.Host, s.cfg.BasePath)

	verifier, challenge, err := generatePKCE()
	if err != nil {
		http.Error(w, "Failed to generate PKCE components", http.StatusInternalServerError)
		return
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "Internal state generator error", http.StatusInternalServerError)
		return
	}
	state := fmt.Sprintf("%x", stateBytes)

	http.SetCookie(w, &http.Cookie{
		Name:     "sam_oidc_state",
		Value:    state,
		Path:     s.cfg.BasePath + "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sam_oidc_verifier",
		Value:    verifier,
		Path:     s.cfg.BasePath + "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})

	oauth2Config := &oauth2.Config{
		ClientID:    s.clientID,
		Endpoint:    s.provider.Endpoint(),
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	authURL := oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("sam_oidc_state")
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state (CSRF verification failed)", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie("sam_oidc_verifier")
	if err != nil || verifierCookie.Value == "" {
		http.Error(w, "Missing verifier cookie", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "sam_oidc_state", Value: "", Path: s.cfg.BasePath + "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "sam_oidc_verifier", Value: "", Path: s.cfg.BasePath + "/", MaxAge: -1})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s%s/auth/callback", scheme, r.Host, s.cfg.BasePath)

	oauth2Config := &oauth2.Config{
		ClientID:    s.clientID,
		Endpoint:    s.provider.Endpoint(),
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	exchangeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	oauth2Token, err := oauth2Config.Exchange(exchangeCtx, code,
		oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value),
	)
	if err != nil {
		http.Error(w, "Failed to exchange auth code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "No id_token field in OAuth2 token response", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sam_session",
		Value:    rawIDToken,
		Path:     s.cfg.BasePath + "/",
		MaxAge:   24 * 3600,
		HttpOnly: true,
		Secure:   scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
}

func (s *Server) HandleSession(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("sam_session")
	if err != nil || sessionCookie.Value == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "No active session"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": sessionCookie.Value,
	})
}

func (s *Server) HandleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"oidc_enabled": s.provider != nil,
	})
}

func generatePKCE() (string, string, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}
