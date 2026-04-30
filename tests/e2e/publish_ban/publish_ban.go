package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

func main() {
	keyHex := flag.String("key", "", "Hub private key (hex)")
	peerToBan := flag.String("peer", "", "Peer ID to ban")
	hubAddr := flag.String("hub", "", "Hub multiaddress")
	flag.Parse()

	if *keyHex == "" || *peerToBan == "" || *hubAddr == "" {
		log.Fatal("Missing required flags")
	}

	keyBytes, err := hex.DecodeString(*keyHex)
	if err != nil {
		log.Fatal(err)
	}
	privKey := ed25519.NewKeyFromSeed(keyBytes)

	ctx := context.Background()

	h, err := libp2p.New()
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		log.Fatal(err)
	}

	addr, err := multiaddr.NewMultiaddr(*hubAddr)
	if err != nil {
		log.Fatal(err)
	}
	addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		log.Fatal(err)
	}

	if err := h.Connect(ctx, *addrInfo); err != nil {
		log.Fatal(err)
	}

	topic, err := ps.Join(api.GossipEvents)
	if err != nil {
		log.Fatal(err)
	}

	event := &api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    *peerToBan,
		Timestamp: time.Now().Unix(),
	}

	// Sign event
	event.Signature = nil
	data, err := proto.Marshal(event)
	if err != nil {
		log.Fatal(err)
	}
	event.Signature = ed25519.Sign(privKey, data)

	eventData, err := proto.Marshal(event)
	if err != nil {
		log.Fatal(err)
	}

	// Wait for pubsub to discover peers
	fmt.Println("Waiting for pubsub peers...")
	for i := 0; i < 30; i++ {
		if len(topic.ListPeers()) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(topic.ListPeers()) == 0 {
		log.Fatal("No pubsub peers found")
	}

	if err := topic.Publish(ctx, eventData); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Published ban event")
}
