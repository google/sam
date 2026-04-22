package reputation

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
)

const TopicV1 = "sam/reputation/v1"

type Attestation struct {
	ReporterID string    `json:"reporter_id"`
	TargetID   string    `json:"target_id"`
	Rating     int       `json:"rating"`
	IssuedAt   time.Time `json:"issued_at"`
	Signature  string    `json:"signature"`
}

type Evaluator interface {
	Score(peerID string) float64
	IsNegative(peerID string) bool
}

type Attestor interface {
	Publish(ctx context.Context, targetID string, rating int) error
}

type TrustStore struct {
	host host.Host
	ps   *pubsub.PubSub

	mu     sync.RWMutex
	scores map[string]float64
	sums   map[string]int
	counts map[string]int
}

func NewTrustStore(h host.Host, ps *pubsub.PubSub) (*TrustStore, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	if ps == nil {
		return nil, fmt.Errorf("gossipsub is nil")
	}
	return &TrustStore{
		host:   h,
		ps:     ps,
		scores: map[string]float64{},
		sums:   map[string]int{},
		counts: map[string]int{},
	}, nil
}

func (s *TrustStore) Start(ctx context.Context) error {
	topic, err := s.ps.Join(TopicV1)
	if err != nil {
		return fmt.Errorf("join reputation topic: %w", err)
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return fmt.Errorf("subscribe reputation topic: %w", err)
	}
	go func() {
		defer sub.Cancel()
		for {
			msg, nextErr := sub.Next(ctx)
			if nextErr != nil {
				return
			}
			if msg == nil || msg.ReceivedFrom == s.host.ID() {
				continue
			}
			var att Attestation
			if err := json.Unmarshal(msg.Data, &att); err != nil {
				continue
			}
			if !s.verify(att) {
				continue
			}
			s.mu.Lock()
			s.sums[att.TargetID] += att.Rating
			s.counts[att.TargetID]++
			s.scores[att.TargetID] = float64(s.sums[att.TargetID]) / float64(s.counts[att.TargetID])
			s.mu.Unlock()
		}
	}()
	return nil
}

func (s *TrustStore) Publish(ctx context.Context, targetID string, rating int) error {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return fmt.Errorf("target peer id is required")
	}
	if rating < -1 || rating > 1 {
		return fmt.Errorf("rating must be -1..1")
	}
	topic, err := s.ps.Join(TopicV1)
	if err != nil {
		return fmt.Errorf("join reputation topic: %w", err)
	}
	att := Attestation{
		ReporterID: s.host.ID().String(),
		TargetID:   targetID,
		Rating:     rating,
		IssuedAt:   time.Now().UTC(),
	}
	sig, err := s.sign(att)
	if err != nil {
		return err
	}
	att.Signature = sig
	payload, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}
	if err := topic.Publish(ctx, payload); err != nil {
		return fmt.Errorf("publish attestation: %w", err)
	}
	// apply locally too
	s.mu.Lock()
	s.sums[targetID] += rating
	s.counts[targetID]++
	s.scores[targetID] = float64(s.sums[targetID]) / float64(s.counts[targetID])
	s.mu.Unlock()
	return nil
}

func (s *TrustStore) Score(peerID string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scores[strings.TrimSpace(peerID)]
}

func (s *TrustStore) IsNegative(peerID string) bool {
	return s.Score(peerID) < 0
}

func (s *TrustStore) sign(att Attestation) (string, error) {
	priv := s.host.Peerstore().PrivKey(s.host.ID())
	if priv == nil {
		return "", fmt.Errorf("host private key unavailable")
	}
	raw, err := priv.Raw()
	if err != nil {
		return "", fmt.Errorf("extract private key bytes: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("unsupported key size")
	}
	payload := []byte(att.ReporterID + "|" + att.TargetID + "|" + fmt.Sprintf("%d", att.Rating) + "|" + att.IssuedAt.UTC().Format(time.RFC3339Nano))
	sig := ed25519.Sign(ed25519.PrivateKey(raw), payload)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *TrustStore) verify(att Attestation) bool {
	if strings.TrimSpace(att.ReporterID) == "" || strings.TrimSpace(att.TargetID) == "" || strings.TrimSpace(att.Signature) == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(att.Signature)
	return err == nil
}

var (
	defaultMu        sync.RWMutex
	defaultEvaluator Evaluator
	defaultAttestor  Attestor
)

func SetDefaultEvaluator(e Evaluator) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultEvaluator = e
}

func SetDefaultAttestor(a Attestor) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultAttestor = a
}

func DefaultEvaluator() Evaluator {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultEvaluator
}

func DefaultAttestor() Attestor {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultAttestor
}
