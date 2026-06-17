package integration_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

var dnsHijackLock sync.Mutex

type FakeDNSServer struct {
	hosts    map[string]net.IP
	txtHosts map[string][]string
	conn     *net.UDPConn
	mu       sync.RWMutex
}

func NewFakeDNSServer(hosts map[string]string, txtHosts map[string][]string) (*FakeDNSServer, error) {
	parsedHosts := make(map[string]net.IP, len(hosts))
	for domain, ipStr := range hosts {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address for domain %s: %s", domain, ipStr)
		}
		parsedHosts[strings.TrimSuffix(domain, ".")] = ip
	}

	parsedTxtHosts := make(map[string][]string, len(txtHosts))
	for domain, txts := range txtHosts {
		parsedTxtHosts[strings.TrimSuffix(domain, ".")] = txts
	}

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	server := &FakeDNSServer{
		hosts:    parsedHosts,
		txtHosts: parsedTxtHosts,
		conn:     conn,
	}
	go server.serve()
	return server, nil
}

func (s *FakeDNSServer) UpdateTXT(domain string, txts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.txtHosts[strings.TrimSuffix(domain, ".")] = txts
}

func (s *FakeDNSServer) serve() {
	buf := make([]byte, 512)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:            msg.Header.ID,
				Response:      true,
				Authoritative: true,
			},
			Questions: msg.Questions,
		}

		if len(msg.Questions) > 0 {
			q := msg.Questions[0]
			domain := strings.TrimSuffix(q.Name.String(), ".")

			s.mu.RLock()
			if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
				if ip, ok := s.hosts[domain]; ok {
					if ipv4 := ip.To4(); ipv4 != nil && q.Type == dnsmessage.TypeA {
						resp.Answers = append(resp.Answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
							Body:   &dnsmessage.AResource{A: [4]byte(ipv4)},
						})
					} else if q.Type == dnsmessage.TypeAAAA && ip.To4() == nil {
						resp.Answers = append(resp.Answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 300},
							Body:   &dnsmessage.AAAAResource{AAAA: [16]byte(ip)},
						})
					}
				}
			} else if q.Type == dnsmessage.TypeTXT {
				if txtRecords, ok := s.txtHosts[domain]; ok {
					for _, txt := range txtRecords {
						resp.Answers = append(resp.Answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 300},
							Body:   &dnsmessage.TXTResource{TXT: []string{txt}},
						})
					}
				}
			}
			s.mu.RUnlock()
		}

		packed, err := resp.Pack()
		if err == nil {
			s.conn.WriteToUDP(packed, addr)
		}
	}
}

func (s *FakeDNSServer) Hijack(t *testing.T) {
	t.Helper()
	dnsHijackLock.Lock()

	originalDial := net.DefaultResolver.Dial
	originalPreferGo := net.DefaultResolver.PreferGo

	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial("udp", s.conn.LocalAddr().String())
	}

	t.Cleanup(func() {
		net.DefaultResolver.Dial = originalDial
		net.DefaultResolver.PreferGo = originalPreferGo
		s.conn.Close()
		dnsHijackLock.Unlock()
	})
}
