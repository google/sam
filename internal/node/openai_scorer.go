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
	"net/http"
	"sort"
	"time"

	"github.com/google/sam/api"
)

// providerBackoff is how long a provider is skipped after a retryable failure.
const providerBackoff = 15 * time.Second

// Rejection reasons for facade provider filtering (metric label values).
const (
	reasonPeerRevoked     = "peer_revoked"
	reasonProviderBackoff = "provider_backoff"
	reasonLabelMismatch   = "label_mismatch"
	// reasonEgressFloorMismatch is kept distinct from reasonLabelMismatch so
	// an operator can tell their own floor apart from a caller's requirement
	// when a request finds no provider.
	reasonEgressFloorMismatch = "egress_floor_mismatch"
	reasonLabelUnattested     = "label_unattested"
	reasonNoEligible          = "no_eligible_provider"
	reasonAttemptsExceeded    = "attempts_exceeded"
)

// floor returns the operator's egress floor, or nil when the seam is unset
// (tests) or no floor is configured.
func (f *openAIFacade) floor() map[string]string {
	if f.egressFloor == nil {
		return nil
	}
	return f.egressFloor()
}

// labelsAllowed reports whether a provider's claimed labels satisfy any
// required key=value pair (exact match).
func labelsAllowed(required, claimed map[string]string) bool {
	for k, v := range required {
		if claimed[k] == v {
			return true
		}
	}
	return false
}

// rankProviders applies hard constraints then orders the survivors: eligible
// locals first, then remotes by ascending advertised load. Providers with no
// load information look idle — without telemetry this degrades to rotation
// among equals. Every exclusion is accounted per reason.
func (f *openAIFacade) rankProviders(providers []modelProvider, requiredLabels map[string]string) []modelProvider {
	var locals, remotes []modelProvider
	for _, p := range providers {
		labels := p.labels
		if p.peerID == "" && f.localLabels != nil {
			labels = f.localLabels()
		} else if len(labels) == 0 && p.peerID != "" && f.peerLabels != nil {
			// Registry-probed providers carry no labels; the gossip view may
			// still know the peer's claims.
			labels = f.peerLabels(p.peerID)
		}
		// Labels are routing hints: a remote whose own claims mismatch the
		// requirement is dropped early, but an unlabeled remote proceeds to
		// the label gate, the authoritative fail-closed check on the
		// provider's biscuit-attested labels (see labels_gate.go). Locals
		// have no gate, so their declared labels stay fail-closed here.
		if len(requiredLabels) > 0 {
			knownMismatch := len(labels) > 0 && !labelsAllowed(requiredLabels, labels)
			if knownMismatch || (p.peerID == "" && !labelsAllowed(requiredLabels, labels)) {
				recordFacadeRejection(reasonLabelMismatch)
				continue
			}
		}
		// The operator's egress floor, which the caller cannot waive. Every
		// pair must hold, so this is not labelsAllowed. A remote is dropped
		// here only on a claim that already contradicts the floor; the gate
		// still decides on attested facts. A local is decided here for good,
		// because it has no biscuit to attest anything.
		if floor := f.floor(); len(floor) > 0 {
			// A local is settled here: its labels are its own configuration,
			// it has no Biscuit, and it never reaches the gate, so the floor
			// must hold in full.
			//
			// A remote is only skipped on a claim that conflicts. Gossip may
			// carry part of what a peer attests, so silence on a pair of the
			// floor is not failure — the gate resolves it on attested facts.
			var outside bool
			if p.peerID == "" {
				outside = !api.LabelsSatisfyFloor(floor, labels)
			} else {
				outside = api.LabelsContradictFloor(floor, labels)
			}
			if outside {
				recordFacadeRejection(reasonEgressFloorMismatch)
				continue
			}
		}
		if p.peerID == "" {
			locals = append(locals, p)
			continue
		}
		if f.isRevoked != nil && f.isRevoked(p.peerID) {
			recordFacadeRejection(reasonPeerRevoked)
			continue
		}
		if f.inBackoff(p) {
			recordFacadeRejection(reasonProviderBackoff)
			continue
		}
		remotes = append(remotes, p)
	}

	sort.SliceStable(remotes, func(i, j int) bool { return remotes[i].active < remotes[j].active })
	rotateEqualHead(remotes)
	return append(locals, remotes...)
}

// rotateEqualHead rotates the group of equally loaded head providers so
// repeated requests spread across them instead of hammering the first.
func rotateEqualHead(remotes []modelProvider) {
	if len(remotes) < 2 {
		return
	}
	group := 1
	for group < len(remotes) && remotes[group].active == remotes[0].active {
		group++
	}
	if group < 2 {
		return
	}
	offset := int(facadeRR.Add(1) % uint64(group))
	head := append([]modelProvider{}, remotes[:group]...)
	for i := range group {
		remotes[i] = head[(i+offset)%group]
	}
}

func backoffKey(p modelProvider) string { return p.peerID + "|" + p.service }

func (f *openAIFacade) inBackoff(p modelProvider) bool {
	f.backoffMu.Lock()
	defer f.backoffMu.Unlock()
	until, ok := f.backoff[backoffKey(p)]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(f.backoff, backoffKey(p))
		return false
	}
	return true
}

func (f *openAIFacade) recordBackoff(p modelProvider) {
	if p.peerID == "" {
		return // locals are not backed off; the service registry owns their lifecycle
	}
	f.backoffMu.Lock()
	defer f.backoffMu.Unlock()
	if f.backoff == nil {
		f.backoff = map[string]time.Time{}
	}
	f.backoff[backoffKey(p)] = time.Now().Add(providerBackoff)
}

// retryableStatus reports provider responses that are safe to retry
// elsewhere: the provider produced no model output.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// attemptWriter defers committing to the client until the provider's status
// is known: retryable statuses are swallowed (body discarded) so the request
// can be retried on the next-ranked provider; anything else streams through.
type attemptWriter struct {
	dst       http.ResponseWriter
	header    http.Header
	status    int
	retryable bool
	started   bool
}

func newAttemptWriter(dst http.ResponseWriter) *attemptWriter {
	return &attemptWriter{dst: dst, header: http.Header{}}
}

func (a *attemptWriter) Header() http.Header { return a.header }

func (a *attemptWriter) WriteHeader(code int) {
	if a.started || a.retryable {
		return
	}
	a.status = code
	if retryableStatus(code) {
		a.retryable = true
		return
	}
	dst := a.dst.Header()
	for k, vv := range a.header {
		dst[k] = vv
	}
	a.dst.WriteHeader(code)
	a.started = true
}

func (a *attemptWriter) Write(p []byte) (int, error) {
	if a.retryable {
		return len(p), nil // discard failed attempt's error body
	}
	if !a.started {
		a.WriteHeader(http.StatusOK)
	}
	return a.dst.Write(p)
}

func (a *attemptWriter) Flush() {
	if !a.started {
		return
	}
	if fl, ok := a.dst.(http.Flusher); ok {
		fl.Flush()
	}
}
