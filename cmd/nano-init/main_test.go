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
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestTheSameNameAlwaysGetsTheSameAddress(t *testing.T) {
	// Clients cache. An agent that resolves once, holds the answer, and
	// connects later must arrive at the same place, or a long-lived agent
	// starts failing for reasons nothing in its own behaviour explains.
	r, err := newResolver("169.254.64.0/18")
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}

	first, err := r.assign("mesh.sam.alt")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	again, err := r.assign("mesh.sam.alt")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	other, err := r.assign("calc.mcp.sam.alt")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}

	if first != again {
		t.Errorf("same name got %v then %v", first, again)
	}
	if first == other {
		t.Errorf("two names share the address %v", first)
	}
}

func TestTheAddressLeadsBackToTheName(t *testing.T) {
	// This is the whole point of the resolver: the boundary must be told a
	// name, because mesh.sam.alt has no address and the boundary is what
	// chooses a provider for it.
	r, err := newResolver("169.254.64.0/18")
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}

	addr, err := r.assign("mesh.sam.alt")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}

	name, ok := r.nameFor(addr)
	if !ok || name != "mesh.sam.alt" {
		t.Errorf("nameFor(%v) = %q, %v; want mesh.sam.alt", addr, name, ok)
	}

	// An address nobody handed out is not an error: an agent may dial a
	// literal address, and whether that is allowed is policy's business.
	if _, ok := r.nameFor(netip.MustParseAddr("93.184.216.34")); ok {
		t.Error("an address that was never assigned resolved to a name")
	}
}

func TestTheAddressPoolIsBounded(t *testing.T) {
	// A /30 holds four addresses, and the network address is skipped. An
	// agent resolving endlessly must be refused rather than handed something
	// outside the pool that would then be routed somewhere real.
	r, err := newResolver("169.254.64.0/30")
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}

	var lastErr error
	for i := range 10 {
		if _, err := r.assign(strings.Repeat("a", i+1) + ".example"); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Error("the pool handed out more addresses than it contains")
	}
}

func TestAQueriesAreAnsweredWithAPlaceholder(t *testing.T) {
	r, err := newResolver("169.254.64.0/18")
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}

	query, err := buildQuery("mesh.sam.alt.", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}

	reply, err := r.answer(query)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}

	var parser dnsmessage.Parser
	if _, err := parser.Start(reply); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	answer, err := parser.AnswerHeader()
	if err != nil {
		t.Fatalf("answer header: %v", err)
	}
	if answer.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want A", answer.Type)
	}

	resource, err := parser.AResource()
	if err != nil {
		t.Fatalf("A resource: %v", err)
	}
	got := netip.AddrFrom4(resource.A)
	if name, ok := r.nameFor(got); !ok || name != "mesh.sam.alt" {
		t.Errorf("answered %v, which maps to %q, %v", got, name, ok)
	}
}

func TestAAAAQueriesAreAnsweredEmpty(t *testing.T) {
	// A sandbox that got an AAAA answer would try IPv6 first and wait for it
	// to fail, which reads as a slow mesh rather than an absent address family.
	r, err := newResolver("169.254.64.0/18")
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}

	query, err := buildQuery("mesh.sam.alt.", dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	reply, err := r.answer(query)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}

	var parser dnsmessage.Parser
	if _, err := parser.Start(reply); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	if _, err := parser.AnswerHeader(); err == nil {
		t.Error("AAAA query produced an answer record")
	}
}

func TestConnectSendsTheNameNotTheAddress(t *testing.T) {
	// If this regresses, the boundary receives an address it cannot resolve a
	// provider for, and every mesh name stops working while every literal
	// address keeps working, which is a confusing way to lose the design.
	request, err := connectRequest("mesh.sam.alt", 80)
	if err != nil {
		t.Fatalf("connectRequest: %v", err)
	}

	if request[3] != atypDomain {
		t.Fatalf("address type = %d, want %d (domain)", request[3], atypDomain)
	}
	length := int(request[4])
	if got := string(request[5 : 5+length]); got != "mesh.sam.alt" {
		t.Errorf("name = %q, want mesh.sam.alt", got)
	}
	port := int(request[5+length])<<8 | int(request[6+length])
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

func TestConnectPassesLiteralAddressesThrough(t *testing.T) {
	// An agent that dials an address rather than a name is not doing anything
	// forbidden; the boundary still decides. Encoding it as a name would make
	// the boundary try to resolve "93.184.216.34" as a mesh service.
	request, err := connectRequest("93.184.216.34", 443)
	if err != nil {
		t.Fatalf("connectRequest: %v", err)
	}
	if request[3] != atypIPv4 {
		t.Errorf("address type = %d, want %d (IPv4)", request[3], atypIPv4)
	}
}

func TestConnectRefusesAnUnencodableName(t *testing.T) {
	if _, err := connectRequest(strings.Repeat("a", 256), 80); err == nil {
		t.Error("a name too long for the protocol was encoded anyway")
	}
}

func TestPolicyDenialIsLegibleAsPolicy(t *testing.T) {
	// An operator reading an agent's logs has to be able to tell "you may not"
	// from "the mesh is broken", because the two have nothing in common.
	if got := replyMessage(0x02); !strings.Contains(got, "not allowed") {
		t.Errorf("reply 0x02 reads as %q, which does not say it was policy", got)
	}
	if got := replyMessage(0x05); !strings.Contains(got, "refused") {
		t.Errorf("reply 0x05 reads as %q", got)
	}
}

func TestTheAgentEnvironmentIsNotDoctored(t *testing.T) {
	// The point of the rewrite: nano-init no longer reaches into the agent. If
	// these come back, confinement has quietly become a request for the
	// agent's cooperation again and every argument for the design stops
	// holding.
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	for _, forbidden := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
		"LD_PRELOAD", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
	} {
		if strings.Contains(string(source), `"`+forbidden+`"`) {
			t.Errorf("%s is being set for the agent again", forbidden)
		}
	}
}

func TestTheBoundaryCanBeNamedEitherWay(t *testing.T) {
	// A container dials a path and a microVM dials vsock. One binary serves
	// both, and nothing else in the sandbox knows which kind it is, so this
	// string is the entire difference between them.
	if _, _, err := parseVsock("2:1080"); err != nil {
		t.Errorf("parseVsock(2:1080): %v", err)
	}
	for _, bad := range []string{"2", "host:1080", "2:not-a-port", ""} {
		if _, _, err := parseVsock(bad); err == nil {
			t.Errorf("parseVsock(%q) was accepted", bad)
		}
	}

	// A missing socket has to be reported at startup. A sandbox that starts
	// without a way out looks like a mesh outage on the agent's first call.
	if err := checkBoundary(filepath.Join(t.TempDir(), "absent.sock")); err == nil {
		t.Error("a boundary socket that does not exist was accepted")
	}
	if err := checkBoundary("vsock://2:1080"); err != nil {
		t.Errorf("a well-formed vsock boundary was rejected: %v", err)
	}
}

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dest := filepath.Join(dir, "dest")

	if err := os.WriteFile(src, []byte("binary"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := copyFile(src, dest); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "binary" {
		t.Errorf("contents = %q, want %q", got, "binary")
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// The copy has to be runnable; the exact bits are the umask's business.
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("mode = %v, want the owner execute bit set", info.Mode().Perm())
	}
}

func buildQuery(name string, qtype dnsmessage.Type) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1234})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}
