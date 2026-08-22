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
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// The sandbox has to keep hold of the name.
//
// An agent asks for mesh.sam.alt, which has no address anywhere: the boundary
// answers it by choosing a provider, and choosing is the whole point. But an
// agent opens a socket to an address, and the packets that arrive at the tun
// carry an address and nothing else. Somewhere between the two the name has to
// survive.
//
// So this hands out an address that means nothing except "the name I was asked
// for", and remembers which. When the flow comes back the other way, the
// address is turned back into the name and it is the name that reaches the
// boundary. The addresses are never real, never routed and never leave the
// sandbox.
//
// This is not the DNS interception that used to live here. That answered with
// real-looking addresses and then relied on the agent honouring proxy
// variables to catch the connection; an agent that ignored them was outside
// the boundary. Here the address is a token in a table, the route is the only
// route, and an agent that ignores everything still arrives at the same place.

// resolver allocates a placeholder address per name and remembers the pairing.
type resolver struct {
	mu    sync.RWMutex
	pool  netip.Prefix
	next  netip.Addr
	names map[netip.Addr]string
	addrs map[string]netip.Addr
}

func newResolver(pool string) (*resolver, error) {
	prefix, err := netip.ParsePrefix(pool)
	if err != nil {
		return nil, fmt.Errorf("virtual address pool %q: %w", pool, err)
	}
	return &resolver{
		pool: prefix,
		// The network address itself is skipped: handing it out would make a
		// name indistinguishable from "no name at all" in a packet capture.
		next:  prefix.Addr().Next(),
		names: map[netip.Addr]string{},
		addrs: map[string]netip.Addr{},
	}, nil
}

// assign returns the placeholder for a name, allocating one if needed. The
// same name always gets the same address, so an agent that resolves twice and
// caches the first answer still reaches the same place.
func (r *resolver) assign(name string) (netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if addr, ok := r.addrs[name]; ok {
		return addr, nil
	}
	if !r.pool.Contains(r.next) {
		return netip.Addr{}, fmt.Errorf("virtual address pool %s exhausted", r.pool)
	}

	addr := r.next
	r.next = r.next.Next()
	r.names[addr] = name
	r.addrs[name] = addr
	return addr, nil
}

// nameFor returns the name a placeholder stands for. An address that was never
// handed out is not an error: an agent may dial a literal address, and that is
// policy's business rather than something to fail here.
func (r *resolver) nameFor(addr netip.Addr) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.names[addr]
	return name, ok
}

// serveDNS answers A queries with placeholders until ctx ends.
//
// Nothing here is a security control. An agent that ignores this resolver and
// hardcodes another one still has its packets routed through the tun, and
// still reaches only what policy allows. This exists so that ordinary clients,
// which resolve before they connect, get an address to connect to.
func (r *resolver) serveDNS(conn net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		reply, err := r.answer(buf[:n])
		if err != nil {
			continue
		}
		if _, err := conn.WriteTo(reply, from); err != nil {
			return
		}
	}
}

// answer builds a reply for one query.
func (r *resolver) answer(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:            header.ID,
		Response:      true,
		Authoritative: true,
		RCode:         dnsmessage.RCodeSuccess,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}

	// Only A is answered. A sandbox that got a AAAA answer would try IPv6
	// first and wait for it to fail, which looks like a slow mesh.
	if question.Type == dnsmessage.TypeA {
		name := trimRoot(question.Name.String())
		addr, err := r.assign(name)
		if err != nil {
			return nil, err
		}
		if err := builder.AResource(
			dnsmessage.ResourceHeader{Name: question.Name, Class: question.Class, TTL: 1},
			dnsmessage.AResource{A: addr.As4()},
		); err != nil {
			return nil, err
		}
	}

	return builder.Finish()
}

func trimRoot(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name[:len(name)-1]
	}
	return name
}
