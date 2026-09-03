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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSamTransportInjectsHeaders(t *testing.T) {
	var gotAuth, gotLabels string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("X-Sam-Authentication")
		gotLabels = r.Header.Get("X-Sam-Required-Labels")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	client := &http.Client{Transport: &samTransport{base: http.DefaultTransport, token: "tok", requiredLabels: "region=eu"}}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("X-Sam-Authentication = %q, want %q", gotAuth, "Bearer tok")
	}
	if gotLabels != "region=eu" {
		t.Errorf("X-Sam-Required-Labels = %q, want %q", gotLabels, "region=eu")
	}
}

func TestSamTransportOmitsEmptyHeaders(t *testing.T) {
	var sawAuth, sawLabels bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawAuth = r.Header["X-Sam-Authentication"]
		_, sawLabels = r.Header["X-Sam-Required-Labels"]
	}))
	defer backend.Close()

	client := &http.Client{Transport: &samTransport{base: http.DefaultTransport}}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if sawAuth || sawLabels {
		t.Fatalf("empty config must not send gate headers (auth=%v labels=%v)", sawAuth, sawLabels)
	}
}

func TestSamTransportMapsRefusalToSidecarError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Required labels not attested by provider", http.StatusForbidden)
	}))
	defer backend.Close()

	client := &http.Client{Transport: &samTransport{base: http.DefaultTransport, token: "tok"}}
	_, err := client.Get(backend.URL)
	if err == nil {
		t.Fatal("403 must surface as an error")
	}
	var se *sidecarError
	if !errors.As(err, &se) {
		t.Fatalf("error %T does not unwrap to *sidecarError: %v", err, err)
	}
	if se.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", se.Status)
	}
	if !strings.Contains(se.Body, "Required labels not attested by provider") {
		t.Errorf("body not verbatim: %q", se.Body)
	}
	if want := "403: Required labels not attested by provider"; se.Error() != want {
		t.Errorf("Error() = %q, want %q", se.Error(), want)
	}
}
