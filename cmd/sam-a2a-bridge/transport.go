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
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Mirrors api.HeaderSamAuthentication / api.HeaderSamRequiredLabels
// (api/network.go:114,133); literals because this module must not
// depend on the root module.
const (
	headerSamAuthentication = "X-Sam-Authentication"
	headerSamRequiredLabels = "X-Sam-Required-Labels"
)

// sidecarError carries a non-2xx sidecar reply so tool handlers can show
// the refusal (e.g. the labels-gate 403) to the harness verbatim.
type sidecarError struct {
	Status int
	Body   string
}

func (e *sidecarError) Error() string {
	return fmt.Sprintf("%d: %s", e.Status, strings.TrimSpace(e.Body))
}

// samTransport injects the local sidecar gate headers on every outbound
// request and converts non-2xx replies into sidecarError.
type samTransport struct {
	base           http.RoundTripper
	token          string
	requiredLabels string
}

func (t *samTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if t.token != "" {
		req.Header.Set(headerSamAuthentication, "Bearer "+t.token)
	}
	if t.requiredLabels != "" {
		req.Header.Set(headerSamRequiredLabels, t.requiredLabels)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, &sidecarError{Status: resp.StatusCode, Body: string(body)}
	}
	return resp, nil
}
