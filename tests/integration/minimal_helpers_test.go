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

package integration_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func buildBinary(t *testing.T, pkgPath string) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), filepath.Base(pkgPath))
	cmd := exec.Command("go", "build", "-o", out, pkgPath)
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s failed: %v\n%s", pkgPath, err, string(output))
	}
	return out
}

func runCommand(
	t *testing.T,
	cwd string,
	timeout time.Duration,
	env []string,
	stdin string,
	name string,
	args ...string,
) (string, string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	if len(env) > 0 {
		cmd.Env = append(cmd.Env, env...)
	}
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout.String(), stderr.String(), context.DeadlineExceeded
	}
	return stdout.String(), stderr.String(), err
}

func startMockLibp2pHub(t *testing.T) (peer.ID, string) {
	t.Helper()

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create mock libp2p host: %v", err)
	}

	kdht, err := dht.New(context.Background(), h, dht.Mode(dht.ModeServer))
	if err != nil {
		t.Fatalf("failed to create DHT on mock hub: %v", err)
	}

	h.SetStreamHandler(api.EnrollProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()

		// The following constants are mock values used for testing.
		// 'mock-biscuit-token' is a dummy token string.
		// 'mock-hub-pub-key' is a dummy public key string.
		resp := &api.EnrollResponse{
			BiscuitToken: []byte("mock-biscuit-token"),
			HubPublicKey: []byte("mock-hub-pub-key"),
			HubAddresses: []string{h.Addrs()[0].String() + "/p2p/" + h.ID().String()},
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			fmt.Printf("Failed to marshal mock response: %v\n", err)
			return
		}
		writer := msgio.NewVarintWriter(s)
		if err := writer.WriteMsg(data); err != nil {
			fmt.Printf("Failed to write mock response: %v\n", err)
		}
	})

	t.Cleanup(func() {
		_ = kdht.Close()
		_ = h.Close()
	})

	return h.ID(), h.Addrs()[0].String() + "/p2p/" + h.ID().String()
}
