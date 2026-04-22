package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"sam/pkg/identity"
)

type passportRequest struct {
	PeerID     string `json:"peer_id"`
	Federation string `json:"federation"`
	Subject    string `json:"subject"`
	Email      string `json:"email"`
}

func main() {
	var listen string
	cmd := &cobra.Command{
		Use:   "sam-hub",
		Short: "Run a SAM hub (passport issuer + trust observer)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})
			mux.HandleFunc("/issue-passport", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				var req passportRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
					return
				}
				tok, err := identity.IssuePassportBiscuit(context.Background(), identity.PassportIssueRequest{
					PeerID:       strings.TrimSpace(req.PeerID),
					FederationID: strings.TrimSpace(req.Federation),
					Subject:      strings.TrimSpace(req.Subject),
					Claims:       map[string]string{"email": strings.TrimSpace(req.Email)},
				})
				if err != nil {
					http.Error(w, fmt.Sprintf("issue failed: %v", err), http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"passport_biscuit": tok})
			})
			mux.HandleFunc("/trust-map", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"source": "gossipsub", "note": "passive observer endpoint"})
			})
			srv := &http.Server{Addr: listen, Handler: mux}
			go func() {
				<-cmd.Context().Done()
				_ = srv.Shutdown(context.Background())
			}()
			return srv.ListenAndServe()
		},
	}
	cmd.Flags().StringVar(&listen, "listen", ":8081", "hub listen address")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "sam-hub: %v\n", err)
		os.Exit(1)
	}
}
