package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/spf13/cobra"
)

var (
	hubAddr     string
	listenAddrs []string
	tokenFlag   string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-node",
		Short: "Sovereign Agent Mesh Node",
	}

	// LOGIN COMMAND: For Headless Environments
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Establish sovereign identity with the Hub",
		Run: func(cmd *cobra.Command, args []string) {
			dataDir, err := GetDataDir()
			if err != nil {
				log.Fatalf("Critical: %v", err)
			}

			store, err := NewStore(dataDir)
			if err != nil {
				log.Fatalf("Critical: %v", err)
			}
			defer store.Close()

			priv := getOrGenerateKey(store)
			// Temporary host to determine PeerID
			tempNode, err := NewSamNode(context.Background(), priv, []string{})
			if err != nil {
				log.Fatalf("Failed to initialize identity: %v", err)
			}

			loginURL := fmt.Sprintf("%s/login?peer_id=%s", hubAddr, tempNode.Host.ID())

			fmt.Println("--- Sovereign Identity Login ---")
			fmt.Printf("1. Please open the following URL in your browser:\n\n   %s\n\n", loginURL)
			fmt.Println("2. Authenticate via your OIDC provider.")
			fmt.Println("3. Copy the 'Identity Biscuit' provided at the end of the flow.")
			fmt.Print("\nPaste your Identity Biscuit here: ")

			reader := bufio.NewReader(os.Stdin)
			token, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalf("Failed to read input: %v", err)
			}
			token = strings.TrimSpace(token)

			if token == "" {
				log.Fatal("Error: No token provided.")
			}

			if err := store.SaveIdentity(token); err != nil {
				log.Fatalf("Failed to save identity: %v", err)
			}

			fmt.Printf("\nSuccess! Identity stored for PeerID: %s\n", tempNode.Host.ID())
		},
	}

	// RUN COMMAND: Start the Mesh
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start the sovereign mesh node",
		Run: func(cmd *cobra.Command, args []string) {
			dataDir, _ := GetDataDir()
			store, err := NewStore(dataDir)
			if err != nil {
				log.Fatalf("Failed to open store: %v", err)
			}
			defer store.Close()

			token := tokenFlag
			if token == "" {
				token, _ = store.LoadIdentity()
			}
			if token == "" {
				fmt.Println("No identity found. Please run 'sam-node login' or provide --token")
				return
			}

			priv := getOrGenerateKey(store)
			node, err := NewSamNode(context.Background(), priv, listenAddrs)
			if err != nil {
				log.Fatalf("Failed to start mesh node: %v", err)
			}

			// Register the mandatory sovereign auth hook
			node.Host.SetStreamHandler(AuthProtocol, node.HandleAuthHandshake)

			fmt.Printf("SAM Node Online.\nPeerID: %s\nListening on: %v\n", node.Host.ID(), listenAddrs)

			// Block forever
			select {}
		},
	}

	// Configure Flags
	runCmd.Flags().StringVar(&tokenFlag, "token", os.Getenv("SAM_NODE_TOKEN"), "Manual Identity Biscuit (overrides store)")
	runCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}, "libp2p Listen Addrs")
	rootCmd.PersistentFlags().StringVar(&hubAddr, "hub", "http://localhost:8080", "Hub URL (Default: app.sam-dev)")

	rootCmd.AddCommand(loginCmd, runCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// getOrGenerateKey retrieves a persistent private key or creates one if it's the first run
func getOrGenerateKey(s *Store) crypto.PrivKey {
	kb, _ := s.LoadKey()
	if len(kb) == 0 {
		fmt.Println("[Store] Generating new Peer Identity...")
		priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		raw, _ := crypto.MarshalPrivateKey(priv)
		s.SaveKey(raw)
		return priv
	}
	priv, err := crypto.UnmarshalPrivateKey(kb)
	if err != nil {
		log.Fatalf("Corrupt key in store: %v", err)
	}
	return priv
}
