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
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <uds-path> <cmd> [args...]", os.Args[0])
	}
	udsPath := os.Args[1]
	cmdName := os.Args[2]
	cmdArgs := os.Args[3:]

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	log.Printf("Bootstrapping CA certificate from UDS: %s", udsPath)
	if err := bootstrapCA(ctx, udsPath); err != nil {
		log.Fatalf("Bootstrap CA failed: %v", err)
	}
	log.Println("Bootstrap CA successfully written to /tmp/ephemeral_ca.pem")

	// 1b. Bootstrap Interceptor
	log.Println("Attempting to bootstrap socket interceptor from UDS gateway...")
	var bootstrappedInterceptor string
	if interceptor, err := bootstrapInterceptor(ctx, udsPath); err != nil {
		log.Printf("Warning: failed to bootstrap socket interceptor: %v. Running without transparent interception.", err)
	} else {
		bootstrappedInterceptor = interceptor
		log.Printf("Socket interceptor successfully written to %s", bootstrappedInterceptor)
	}

	// 2. DNS Spoofer
	dnsPort := os.Getenv("SAM_DNS_PORT")
	if dnsPort == "" {
		dnsPort = "53"
	}
	dnsAddr := "127.0.0.1:" + dnsPort
	if err := startDNSSpoofer(ctx, dnsAddr); err != nil {
		log.Fatalf("Failed to start DNS spoofer: %v", err)
	}
	log.Printf("DNS spoofer listening on UDP %s", dnsAddr)

	// Overwrite /etc/resolv.conf
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver 127.0.0.1\n"), 0644); err != nil {
		log.Printf("Warning: failed to overwrite /etc/resolv.conf: %v", err)
	} else {
		log.Println("Overwrote /etc/resolv.conf to nameserver 127.0.0.1")
	}

	// 3. TCP Forwarding
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to bind random TCP port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	assignedProxyPort := listener.Addr().(*net.TCPAddr).Port
	log.Printf("Blind UDS-forwarder listening on random port 127.0.0.1:%d", assignedProxyPort)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("TCP Accept error: %v", err)
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			go handleConnection(conn, udsPath)
		}
	}()

	// 4. Execution of the target process
	cmd := exec.CommandContext(ctx, cmdName, cmdArgs...)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = 5 * time.Second

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Inject environment variables
	interceptorPath := os.Getenv("SAM_INTERCEPTOR_PATH")
	if interceptorPath == "" {
		interceptorPath = bootstrappedInterceptor
	}
	cmd.Env = buildAgentEnv(assignedProxyPort, "/tmp/ephemeral_ca.pem", interceptorPath)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	agentExitStatus := make(chan syscall.WaitStatus, 1)
	setupPID1Duties(cmd.Process.Pid, agentExitStatus)

	waitErr := cmd.Wait()
	cancel()

	var status syscall.WaitStatus
	hasStatus := false

	if waitErr != nil && errors.Is(waitErr, syscall.ECHILD) {
		status = <-agentExitStatus
		hasStatus = true
	}

	if hasStatus {
		if status.Signaled() {
			os.Exit(128 + int(status.Signal()))
		}
		os.Exit(status.ExitStatus())
	}

	if waitErr != nil {
		if exitError, ok := waitErr.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
}

func bootstrapCA(ctx context.Context, udsPath string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", udsPath)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/internal/bootstrap/ca.crt", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	caBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return os.WriteFile("/tmp/ephemeral_ca.pem", caBytes, 0644)
}

func bootstrapInterceptor(ctx context.Context, udsPath string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", udsPath)
			},
		},
		Timeout: 5 * time.Second,
	}

	arch := runtime.GOARCH
	libc := detectLibc()

	urlStr := fmt.Sprintf("http://localhost/internal/bootstrap/libinterceptor.so?arch=%s&libc=%s", arch, libc)
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned status: %s", resp.Status)
	}

	soBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	targetPath := "/tmp/libinterceptor.so"
	if err := os.WriteFile(targetPath, soBytes, 0755); err != nil {
		return "", err
	}

	return targetPath, nil
}

func detectLibc() string {
	paths := []string{
		"/lib/ld-musl-x86_64.so.1",
		"/lib/ld-musl-aarch64.so.1",
		"/lib/ld-musl-arm.so.1",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return "musl"
		}
	}

	// Also scan directories as fallback
	if files, err := os.ReadDir("/lib"); err == nil {
		for _, f := range files {
			if strings.Contains(strings.ToLower(f.Name()), "musl") {
				return "musl"
			}
		}
	}
	if files, err := os.ReadDir("/lib64"); err == nil {
		for _, f := range files {
			if strings.Contains(strings.ToLower(f.Name()), "musl") {
				return "musl"
			}
		}
	}

	return "glibc"
}

func startDNSSpoofer(ctx context.Context, dnsAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", dnsAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go func() {
		buf := make([]byte, 512)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("DNS Server read error: %v", err)
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}

			packet := make([]byte, n)
			copy(packet, buf[:n])

			go func(p []byte, rAddr *net.UDPAddr) {
				var msg dnsmessage.Message
				if err := msg.Unpack(p); err != nil {
					return
				}

				resp := dnsmessage.Message{
					Header: dnsmessage.Header{
						ID:            msg.ID,
						Response:      true,
						Authoritative: true,
					},
					Questions: msg.Questions,
				}

				if len(msg.Questions) > 0 {
					q := msg.Questions[0]
					switch q.Type {
					case dnsmessage.TypeA:
						resp.Answers = append(resp.Answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
							Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
						})
					case dnsmessage.TypeAAAA:
						ip := net.ParseIP("::1").To16()
						var aaaa [16]byte
						copy(aaaa[:], ip)
						resp.Answers = append(resp.Answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 300},
							Body:   &dnsmessage.AAAAResource{AAAA: aaaa},
						})
					}
				}

				packed, err := resp.Pack()
				if err == nil {
					_, _ = conn.WriteToUDP(packed, rAddr)
				}
			}(packet, remoteAddr)
		}
	}()

	return nil
}

func handleConnection(client net.Conn, udsPath string) {
	defer func() { _ = client.Close() }()

	uds, err := net.DialTimeout("unix", udsPath, 5*time.Second)
	if err != nil {
		log.Printf("UDS Dial error: %v", err)
		return
	}
	defer func() { _ = uds.Close() }()

	cp := func(dst, src net.Conn, done chan<- struct{}) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}

	done := make(chan struct{}, 2)
	go cp(uds, client, done)
	go cp(client, uds, done)

	<-done
	<-done
}

func setupPID1Duties(agentPid int, exitChan chan<- syscall.WaitStatus) {
	sigCh := make(chan os.Signal, 10)
	signal.Notify(sigCh, syscall.SIGCHLD)

	go func() {
		reap := func() {
			for {
				var status syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					break
				}
				if pid == agentPid {
					select {
					case exitChan <- status:
					default:
					}
				}
			}
		}
		// Initial reap pass to catch any processes that exited before signal.Notify was registered
		reap()
		for range sigCh {
			reap()
		}
	}()
}

func buildAgentEnv(assignedPort int, caPath string, interceptorPath string) []string {
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", assignedPort)

	overrides := map[string]string{
		"SSL_CERT_FILE":       caPath,
		"REQUESTS_CA_BUNDLE":  caPath,
		"NODE_EXTRA_CA_CERTS": caPath,
		"HTTP_PROXY":          proxyURL,
		"HTTPS_PROXY":         proxyURL,
		"ALL_PROXY":           proxyURL,
		"http_proxy":          proxyURL,
		"https_proxy":         proxyURL,
		"all_proxy":           proxyURL,
		"SAM_PROXY_PORT":      strconv.Itoa(assignedPort),
	}

	if interceptorPath != "" {
		overrides["LD_PRELOAD"] = interceptorPath
	}

	var result []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		if _, exists := overrides[key]; exists {
			continue
		}
		result = append(result, env)
	}

	for k, v := range overrides {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}

	return result
}
