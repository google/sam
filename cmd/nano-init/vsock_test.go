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
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The vsock path is the microVM's only way out, and it is the one part of this
// program that cannot be exercised by the container sandbox. Left untested it
// would be discovered on a cloud VM in the middle of a scale run, which is an
// expensive place to find out that a socket option is wrong.
//
// Linux can loop vsock back to the host, so none of this needs a VM: the guest
// side of a real Firecracker connection makes the same calls against the same
// kernel code.

// vsockLoopback is VMADDR_CID_LOCAL, the CID that means "this machine".
const vsockLoopback = 1

func TestDialBoundaryOverVsock(t *testing.T) {
	listener, port := listenVsock(t)
	defer func() { _ = unix.Close(listener) }()

	accepted := make(chan []byte, 1)
	go func() {
		fd, _, err := unix.Accept(listener)
		if err != nil {
			accepted <- nil
			return
		}
		defer func() { _ = unix.Close(fd) }()

		buf := make([]byte, 5)
		if _, err := unix.Read(fd, buf); err != nil {
			accepted <- nil
			return
		}
		_, _ = unix.Write(fd, []byte("PONG"))
		accepted <- buf
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialBoundary(ctx, vsockSpec(port))
	if err != nil {
		t.Fatalf("dialBoundary over vsock: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("HELLO")); err != nil {
		t.Fatalf("write: %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply) != "PONG" {
		t.Errorf("reply = %q, want PONG", reply)
	}

	if got := <-accepted; string(got) != "HELLO" {
		t.Errorf("boundary received %q, want HELLO", got)
	}
}

func TestVsockConnectionIsAUsableNetConn(t *testing.T) {
	// The connection is handed to gVisor as an ordinary net.Conn and spliced
	// against sandbox traffic, so deadlines and Close have to work. A raw
	// descriptor wrapped carelessly satisfies the interface and then blocks
	// forever on a read that should have timed out.
	listener, port := listenVsock(t)
	defer func() { _ = unix.Close(listener) }()

	go func() {
		fd, _, err := unix.Accept(listener)
		if err != nil {
			return
		}
		// Accept and then say nothing, so the read below has to time out.
		time.Sleep(3 * time.Second)
		_ = unix.Close(fd)
	}()

	conn, err := dialBoundary(context.Background(), vsockSpec(port))
	if err != nil {
		t.Fatalf("dialBoundary: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("a read with an expired deadline returned no error")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Errorf("read error = %v, want a timeout", err)
	}
}

func TestDialBoundaryReportsAnAbsentVsocklistener(t *testing.T) {
	// A microVM whose host is not listening must fail loudly. Hanging would
	// look to the agent like a slow mesh rather than an absent one.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Port 1 is not something this test ever binds.
	if _, err := dialBoundary(ctx, "vsock://1:1"); err == nil {
		t.Error("dialling a vsock port nobody listens on returned no error")
	}
}

// listenVsock binds a loopback vsock listener and returns it with its port.
func listenVsock(t *testing.T) (fd, port int) {
	t.Helper()

	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no AF_VSOCK on this kernel: %v", err)
	}

	// Port 0 asks the kernel to choose, so concurrent runs cannot collide.
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 0}); err != nil {
		_ = unix.Close(fd)
		t.Skipf("cannot bind vsock (is vsock_loopback loaded?): %v", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		_ = unix.Close(fd)
		t.Skipf("cannot listen on vsock: %v", err)
	}

	sa, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatalf("Getsockname: %v", err)
	}
	vm, ok := sa.(*unix.SockaddrVM)
	if !ok {
		_ = unix.Close(fd)
		t.Fatalf("Getsockname returned %T, want *unix.SockaddrVM", sa)
	}
	return fd, int(vm.Port)
}

func vsockSpec(port int) string {
	return "vsock://" + itoa(vsockLoopback) + ":" + itoa(port)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}
