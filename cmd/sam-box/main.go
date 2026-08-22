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

// Command sam-box is the sandbox dataplane: one per agent sandbox, serving the
// boundary an agent's traffic leaves through.
//
// It holds no libp2p host, no enrollment and no mesh identity of its own. It
// consumes a local sam-node over that node's API socket and offers the sandbox
// a curated surface: mesh inference and tools addressed by name, plus whatever
// egress policy allows. The node's own API stays on the node's side of the
// boundary.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	golog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/sambox"
)

var logger = golog.Logger("sam-box")

func main() {
	var (
		sandboxSocket string
		sidecarSocket string
		bundlePath    string
		egressAllow   []string
		issuer        string
		audience      string
		insecure      bool
		metricsAddr   string
		logLevel      string

		agentIngressSocket string
	)

	rootCmd := &cobra.Command{
		Use:   "sam-box",
		Short: "Sovereign Agent Mesh sandbox gateway",
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Serve the sandbox boundary for an agent",
		Long: "Serves SOCKS5 on a sandbox-facing Unix socket, so an unmodified agent reaches\n" +
			"mesh inference and tools by name, and reaches nothing else unless egress policy\n" +
			"allows it.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			golog.SetAllLoggers(golog.LevelInfo)
			if lvl, err := golog.LevelFromString(logLevel); err == nil {
				golog.SetAllLoggers(lvl)
			}

			agentID, egress, err := resolveAgent(bundlePath, egressAllow, cmd.Flags().Changed("egress-allow"))
			if err != nil {
				return err
			}
			if err := verifyBundleCredential(cmd.Context(), bundlePath, issuer, audience, insecure); err != nil {
				return err
			}
			ingress, err := resolveIngress(bundlePath, sidecarSocket, agentIngressSocket)
			if err != nil {
				return err
			}
			if ingress != nil {
				defer ingress.Close(context.WithoutCancel(cmd.Context()))
			}

			listener, err := sambox.ListenSandboxSocket(sandboxSocket)
			if err != nil {
				return err
			}
			defer func() {
				_ = listener.Close()
				_ = os.Remove(sandboxSocket)
			}()

			if metricsAddr != "" {
				if _, err := sambox.ServeMetrics(cmd.Context(), metricsAddr); err != nil {
					return fmt.Errorf("serve metrics: %w", err)
				}
				logger.Infof("Serving metrics on http://%s/metrics", metricsAddr)
			}

			server := &sambox.SOCKS5Server{
				Dialer: &sambox.AgentDialer{
					Router:        &sambox.Router{Egress: egress},
					SidecarSocket: sidecarSocket,
					AgentID:       agentID,
					Ingress:       ingress,
				},
			}

			logger.Infof("Sandbox boundary listening on %s, node at %s", sandboxSocket, sidecarSocket)
			if agentID == "" {
				logger.Warn("No agent bundle: this sandbox is unidentified, and mesh policy will see only the node it came through")
			} else {
				logger.Infof("Serving agent %s", agentID)
			}
			logger.Infof("Agents reach the mesh at http://%s", api.MeshEntrypointHost)

			if err := server.Serve(cmd.Context(), listener); err != nil {
				return err
			}
			logger.Info("Sandbox boundary stopped")
			return nil
		},
	}

	runCmd.Flags().StringVar(&sandboxSocket, "socket", "", "Path to the sandbox-facing Unix socket to serve SOCKS5 on (required)")
	runCmd.Flags().StringVar(&sidecarSocket, "sidecar-socket", "", "Path to the local sam-node API Unix socket (required)")
	runCmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to the agent bundle declaring the agent's identity and its egress allowance")
	runCmd.Flags().StringSliceVar(&egressAllow, "egress-allow", nil, "Destinations an unidentified sandbox may reach, e.g. api.github.com or *.pypi.org; use --bundle instead where an agent has an identity")
	runCmd.Flags().StringVar(&issuer, "credential-issuer", "", "Issuer whose credentials attest an agent's identity, e.g. a cluster's service-account issuer; required with --bundle")
	runCmd.Flags().StringVar(&audience, "credential-audience", "", "Audience an agent's credential must be scoped to; required with --bundle")
	runCmd.Flags().BoolVar(&insecure, "insecure-unverified-bundle", false, "Trust the bundle's declared identity without a credential to back it, letting whoever can write the file decide which agent this sandbox is")
	runCmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "Serve unauthenticated Prometheus metrics on this address, e.g. 127.0.0.1:9600; off by default")
	runCmd.Flags().StringVar(&agentIngressSocket, "agent-ingress-socket", "", "Path to the sandbox's reverse channel, served by nano-init --ingress-socket; required to reach an agent that serves the mesh, because an isolated sandbox cannot be dialled")
	runCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	for _, required := range []string{"socket", "sidecar-socket"} {
		if err := runCmd.MarkFlagRequired(required); err != nil {
			panic(err)
		}
	}

	rootCmd.AddCommand(runCmd)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		logger.Fatalf("%v", err)
	}
}

// resolveAgent settles who this boundary serves. A bundle is the real answer;
// --egress-allow covers a sandbox with no identity yet, which mesh policy can
// only attribute to the node it came through. Accepting both would leave the
// egress allowance ambiguous, so it is refused rather than silently resolved.
func resolveAgent(bundlePath string, egressAllow []string, egressSet bool) (string, *sambox.EgressPolicy, error) {
	if bundlePath == "" {
		policy, err := sambox.NewEgressPolicy(egressAllow)
		return "", policy, err
	}
	if egressSet {
		return "", nil, fmt.Errorf("--bundle already declares the egress allowance; drop --egress-allow")
	}

	bundle, err := sambox.LoadAgentBundle(bundlePath)
	if err != nil {
		return "", nil, err
	}
	return bundle.Agent.ID, bundle.EgressPolicy(), nil
}

// verifyBundleCredential checks that the bundle is backed by a credential the
// platform issued to this workload.
//
// A bundle that is not verified is self-asserting: whoever can write the file
// picks the agent, and the identity the whole mesh reasons about rests on a
// YAML field. That is a real choice an operator may need to make, so it is
// available -- but it has to be made explicitly, in a flag that is visible in a
// process listing and a pod spec, rather than by leaving something unset.
//
// The issuer is an operator flag and never a bundle field, because the bundle
// travels with the agent: an issuer named there could be one the attacker
// controls, and their self-signed credential would verify perfectly.
func verifyBundleCredential(ctx context.Context, bundlePath, issuer, audience string, insecure bool) error {
	if bundlePath == "" {
		// No bundle is not a weak claim, it is no claim: the sandbox is
		// unidentified and mesh policy sees only the node it came through.
		return nil
	}

	if insecure {
		if issuer != "" || audience != "" {
			return fmt.Errorf("--insecure-unverified-bundle contradicts --credential-issuer; pick one")
		}
		logger.Warn("--insecure-unverified-bundle: this bundle is taken at its word, so whoever can write it decides which agent this sandbox is")
		return nil
	}

	if issuer == "" || audience == "" {
		return fmt.Errorf("--bundle needs --credential-issuer and --credential-audience so the agent it names can be checked" +
			" against the credential the platform issued; pass --insecure-unverified-bundle to run without that check")
	}

	verifier, err := sambox.NewWorkloadVerifier(ctx, issuer, audience)
	if err != nil {
		return err
	}
	bundle, err := sambox.LoadAgentBundle(bundlePath)
	if err != nil {
		return err
	}
	if err := verifier.Verify(ctx, bundle); err != nil {
		return err
	}
	logger.Infof("Credential verified: %s is %s", bundle.Agent.ID, bundle.Agent.ExternalID)
	return nil
}

// resolveIngress prepares what the agent is permitted to serve. Nil means
// nothing, which is the case for a sandbox that only calls out.
func resolveIngress(bundlePath, sidecarSocket, agentIngressSocket string) (*sambox.IngressManager, error) {
	if bundlePath == "" {
		return nil, nil
	}
	bundle, err := sambox.LoadAgentBundle(bundlePath)
	if err != nil {
		return nil, err
	}
	if len(bundle.Ingress) == 0 {
		return nil, nil
	}
	if agentIngressSocket == "" {
		// Refused rather than degraded. Without a channel into the sandbox the
		// only address left is one in this process's network namespace, which
		// is the pod's: the node's API and every sidecar are on that loopback,
		// and the port would be the agent's to choose.
		return nil, fmt.Errorf("agent %s may serve %d mesh service(s), but --agent-ingress-socket is not set. "+
			"Point it at the path nano-init --ingress-socket serves; without it there is no way into the "+
			"sandbox, and delivering to this process's own network namespace would reach the gateway's "+
			"neighbours instead of the agent", bundle.Agent.ID, len(bundle.Ingress))
	}
	logger.Infof("Agent %s may serve %d mesh service(s) once it announces them", bundle.Agent.ID, len(bundle.Ingress))
	return &sambox.IngressManager{
		SidecarSocket: sidecarSocket,
		Allowed:       bundle.Ingress,
		AgentSocket:   agentIngressSocket,
	}, nil
}
