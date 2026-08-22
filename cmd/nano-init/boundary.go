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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// Everything the sandbox sends leaves through here, as a SOCKS5 CONNECT naming
// a destination. The boundary on the far side decides whether that destination
// is allowed; this end decides nothing, which is deliberate. A sandbox that
// could rule on its own traffic would be ruling on behalf of the agent it
// contains.

const (
	socks5Version  = 0x05
	authNone       = 0x00
	cmdConnect     = 0x01
	atypIPv4       = 0x01
	atypDomain     = 0x03
	atypIPv6       = 0x04
	replySucceeded = 0x00

	boundaryDialTimeout = 30 * time.Second
)

// boundaryProxy carries sandbox flows to sam-box, restoring the name the agent
// asked for. It satisfies tun2socks's proxy.Proxy.
type boundaryProxy struct {
	socket   string
	resolver *resolver
}

// DialContext opens one flow to the boundary.
func (b *boundaryProxy) DialContext(ctx context.Context, meta *M.Metadata) (net.Conn, error) {
	// The address gvisor saw is a placeholder standing for a name, unless the
	// agent dialled a literal address. Either way what arrives at the boundary
	// is what the agent actually asked for.
	host := meta.DstIP.String()
	if name, ok := b.resolver.nameFor(meta.DstIP); ok {
		host = name
	}

	conn, err := dialBoundary(ctx, b.socket)
	if err != nil {
		return nil, fmt.Errorf("dial boundary %s: %w", b.socket, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := connect(conn, host, meta.DstPort); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// The handshake deadline must not become the flow's deadline: an agent
	// holding a long-lived stream would otherwise be cut off mid-conversation.
	_ = conn.SetDeadline(time.Time{})

	return conn, nil
}

// DialUDP refuses. The boundary does not offer UDP ASSOCIATE, by design: a
// datagram path would be a second way out with its own rules, and one way out
// is the property the whole arrangement rests on.
func (b *boundaryProxy) DialUDP(*M.Metadata) (net.PacketConn, error) {
	return nil, errors.New("nano-init: the boundary carries TCP only")
}

// connect performs the SOCKS5 handshake for one destination.
func connect(conn net.Conn, host string, port uint16) error {
	if _, err := conn.Write([]byte{socks5Version, 1, authNone}); err != nil {
		return fmt.Errorf("socks greeting: %w", err)
	}

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return fmt.Errorf("socks greeting reply: %w", err)
	}
	if greeting[0] != socks5Version || greeting[1] != authNone {
		return fmt.Errorf("socks greeting refused: %v", greeting)
	}

	request, err := connectRequest(host, port)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("socks connect: %w", err)
	}

	return readReply(conn)
}

// connectRequest encodes a CONNECT for a name or an address.
func connectRequest(host string, port uint16) ([]byte, error) {
	request := []byte{socks5Version, cmdConnect, 0x00}

	switch ip := net.ParseIP(host); {
	case ip == nil:
		// A name. This is the case that matters: the boundary resolves it.
		if len(host) > 255 {
			return nil, fmt.Errorf("destination name too long: %d bytes", len(host))
		}
		request = append(request, atypDomain, byte(len(host)))
		request = append(request, host...)
	case ip.To4() != nil:
		request = append(request, atypIPv4)
		request = append(request, ip.To4()...)
	default:
		request = append(request, atypIPv6)
		request = append(request, ip.To16()...)
	}

	return binary.BigEndian.AppendUint16(request, port), nil
}

// readReply consumes the SOCKS5 reply, including the bound address the
// boundary reports but nothing here needs.
func readReply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks reply: %w", err)
	}
	if head[0] != socks5Version {
		return fmt.Errorf("socks reply version %d", head[0])
	}
	if head[1] != replySucceeded {
		return fmt.Errorf("boundary refused: %s", replyMessage(head[1]))
	}

	var skip int
	switch head[3] {
	case atypIPv4:
		skip = net.IPv4len
	case atypIPv6:
		skip = net.IPv6len
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fmt.Errorf("socks reply address: %w", err)
		}
		skip = int(length[0])
	default:
		return fmt.Errorf("socks reply address type %d", head[3])
	}

	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return fmt.Errorf("socks reply address: %w", err)
	}
	return nil
}

// replyMessage turns a SOCKS5 failure into something an agent's logs can be
// read against. "Not allowed" is a policy decision and has to be legible as
// one, rather than looking like the mesh being broken.
func replyMessage(code byte) string {
	switch code {
	case 0x02:
		return "not allowed by policy"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "general failure (" + strconv.Itoa(int(code)) + ")"
	}
}
