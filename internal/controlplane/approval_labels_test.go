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

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// There are three ways a node gets a token: OIDC /register, bootstrap
// auto-approve, and bootstrap with an admin approving the pending request. The
// labels ride along on all three and are signed into label() facts that peers
// gate on. Approval attests that the identity may join; nothing makes an admin
// read the labels attached to the request before clicking approve, so the role
// grant has to bound them here too. Otherwise the three paths disagree and the
// approval one is the way around the other two.
func TestApprovalRefusesLabelsTheRoleDoesNotGrant(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()
	srv.config.AdminToken = "super-secret-admin-token"
	srv.config.AutoApproveEnrollment = false
	client := &http.Client{Timeout: 5 * time.Second}

	seedPolicy := func(t *testing.T, allowedLabels []string) {
		t.Helper()
		roles := []*api.PolicyRole{{Name: api.RoleNode, AllowedLabels: allowedLabels}}
		if err := store.SaveMeshPolicy(ctx, roles, nil); err != nil {
			t.Fatalf("SaveMeshPolicy: %v", err)
		}
	}

	// Returns the status of the approval, having taken a fresh peer all the way
	// from bootstrap token to a pending request.
	approveWithLabels := func(t *testing.T, labels map[string]string) int {
		t.Helper()

		adminReq, err := http.NewRequest(http.MethodPost, baseURL+"/admin/bootstrap-tokens",
			bytes.NewBufferString(`{"role":"`+api.RoleNode+`","ttl_hours":2,"max_usages":2}`))
		if err != nil {
			t.Fatal(err)
		}
		adminReq.Header.Set("Content-Type", "application/json")
		adminReq.Header.Set("Authorization", "Bearer super-secret-admin-token")
		resp, err := client.Do(adminReq)
		if err != nil {
			t.Fatalf("create bootstrap token: %v", err)
		}
		var tokenDetails struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
		_ = resp.Body.Close()
		if tokenDetails.Token == "" {
			t.Fatal("empty bootstrap token")
		}

		priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		pID, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := crypto.MarshalPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}

		enrollTS := time.Now().UnixMilli()
		enrollSig, err := priv.Sign(api.EnrollChallenge(pID.String(), enrollTS))
		if err != nil {
			t.Fatal(err)
		}
		enrollData, err := proto.Marshal(&api.BootstrapEnrollRequest{
			BootstrapToken:     tokenDetails.Token,
			PeerId:             pID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleNode,
			Labels:             labels,
			Timestamp:          enrollTS,
			ChallengeSignature: enrollSig,
		})
		if err != nil {
			t.Fatal(err)
		}
		resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewReader(enrollData))
		if err != nil {
			t.Fatalf("POST /enroll: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /enroll status %d: %s", resp.StatusCode, body)
		}

		listReq, err := http.NewRequest(http.MethodGet, baseURL+"/admin/enrollments", nil)
		if err != nil {
			t.Fatal(err)
		}
		listReq.Header.Set("Authorization", "Bearer super-secret-admin-token")
		resp, err = client.Do(listReq)
		if err != nil {
			t.Fatalf("GET /admin/enrollments: %v", err)
		}
		var pending []storage.EnrollmentRequest
		_ = json.NewDecoder(resp.Body).Decode(&pending)
		_ = resp.Body.Close()

		var reqID string
		for _, p := range pending {
			if p.PeerID == pID.String() {
				reqID = p.ID
			}
		}
		if reqID == "" {
			t.Fatalf("no pending request for %s", pID)
		}

		approveReq, err := http.NewRequest(http.MethodPost, baseURL+"/admin/enrollments/"+reqID+"/approve", nil)
		if err != nil {
			t.Fatal(err)
		}
		approveReq.Header.Set("Authorization", "Bearer super-secret-admin-token")
		resp, err = client.Do(approveReq)
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("a granted label is approved", func(t *testing.T) {
		seedPolicy(t, []string{"region=*"})
		if got := approveWithLabels(t, map[string]string{"region": "emea"}); got != http.StatusOK {
			t.Errorf("approval status = %d, want %d", got, http.StatusOK)
		}
	})

	t.Run("approving does not launder an ungranted label", func(t *testing.T) {
		seedPolicy(t, []string{"region=*"})
		if got := approveWithLabels(t, map[string]string{"team": "platform"}); got != http.StatusForbidden {
			t.Errorf("approval status = %d, want %d", got, http.StatusForbidden)
		}
	})

	t.Run("a role granting no labels approves an unlabelled request", func(t *testing.T) {
		seedPolicy(t, nil)
		if got := approveWithLabels(t, nil); got != http.StatusOK {
			t.Errorf("approval status = %d, want %d", got, http.StatusOK)
		}
	})

	t.Run("a role granting no labels refuses a labelled one", func(t *testing.T) {
		seedPolicy(t, nil)
		if got := approveWithLabels(t, map[string]string{"region": "emea"}); got != http.StatusForbidden {
			t.Errorf("approval status = %d, want %d", got, http.StatusForbidden)
		}
	})
}
