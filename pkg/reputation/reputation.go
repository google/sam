package reputation

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"

	internaldb "sam/internal/db"
)

const TopicV1 = "sam/reputation/v1"

type Attestation struct {
	TargetPeerID   string    `json:"target_peer_id"`
	Score          int       `json:"score"`
	Protocol       string    `json:"protocol"`
	Timestamp      time.Time `json:"timestamp"`
	Signature      string    `json:"signature"`
	ReporterPeerID string    `json:"reporter_peer_id,omitempty"`
}

type Evaluator interface {
	Score(peerID string) float64
	IsNegative(peerID string) bool
}

type Attestor interface {
	Publish(ctx context.Context, targetID string, rating int) error
	PublishWithProtocol(ctx context.Context, targetID string, rating int, protocol string) error
}

type TrustStore struct {
	host host.Host
	ps   *pubsub.PubSub

	mu     sync.RWMutex
	scores map[string]float64
	sums   map[string]int
	counts map[string]int
	store  internaldb.Store
}

const trustCacheKey = "trust-cache-v1"

type trustCacheSnapshot struct {
	Scores map[string]float64 `json:"scores"`
	Sums   map[string]int     `json:"sums"`
	Counts map[string]int     `json:"counts"`
}

func NewTrustStore(h host.Host, ps *pubsub.PubSub) (*TrustStore, error) {
	if h == nil {
		return nil, fmt.Errorf("host is nil")
	}
	if ps == nil {
		return nil, fmt.Errorf("gossipsub is nil")
	}
	ts := &TrustStore{
		host:   h,
		ps:     ps,
		scores: map[string]float64{},
		sums:   map[string]int{},
		counts: map[string]int{},
	}
	store, err := internaldb.OpenDefault()
	if err == nil {
		ts.store = store
		if loadErr := ts.loadCache(context.Background()); loadErr != nil {
			_ = ts.store.Close()
			ts.store = nil
		}
	}
	return ts, nil
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
			s.sums[att.TargetPeerID] += att.Score
			s.counts[att.TargetPeerID]++
			s.scores[att.TargetPeerID] = float64(s.sums[att.TargetPeerID]) / float64(s.counts[att.TargetPeerID])
			s.mu.Unlock()
			_ = s.persistCache(context.Background())
		}
	}()
	return nil
}

func (s *TrustStore) Publish(ctx context.Context, targetID string, rating int) error {
	return s.PublishWithProtocol(ctx, targetID, rating, "/sam/a2a/1.0.0")
}

func (s *TrustStore) PublishWithProtocol(ctx context.Context, targetID string, rating int, protocol string) error {
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
		ReporterPeerID: s.host.ID().String(),
		TargetPeerID:   targetID,
		Score:          rating,
		Protocol:       strings.TrimSpace(protocol),
		Timestamp:      time.Now().UTC(),
	}
	if att.Protocol == "" {
		att.Protocol = "/sam/a2a/1.0.0"
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
	_ = s.persistCache(context.Background())
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
	payload := []byte(att.ReporterPeerID + "|" + att.TargetPeerID + "|" + fmt.Sprintf("%d", att.Score) + "|" + att.Protocol + "|" + att.Timestamp.UTC().Format(time.RFC3339Nano))
	sig := ed25519.Sign(ed25519.PrivateKey(raw), payload)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *TrustStore) verify(att Attestation) bool {
	if strings.TrimSpace(att.ReporterPeerID) == "" || strings.TrimSpace(att.TargetPeerID) == "" || strings.TrimSpace(att.Signature) == "" {
		return false
	}
	if strings.TrimSpace(att.Protocol) == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(att.Signature)
	return err == nil
}

func (s *TrustStore) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Close()
}

func (s *TrustStore) loadCache(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	raw, err := s.store.Get(ctx, internaldb.BucketReputation, trustCacheKey)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("loading trust cache: %w", err)
	}
	var snap trustCacheSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("decoding trust cache: %w", err)
	}
	if snap.Scores != nil {
		s.scores = snap.Scores
	}
	if snap.Sums != nil {
		s.sums = snap.Sums
	}
	if snap.Counts != nil {
		s.counts = snap.Counts
	}
	return nil
}

func (s *TrustStore) persistCache(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	s.mu.RLock()
	snap := trustCacheSnapshot{Scores: map[string]float64{}, Sums: map[string]int{}, Counts: map[string]int{}}
	for k, v := range s.scores {
		snap.Scores[k] = v
	}
	for k, v := range s.sums {
		snap.Sums[k] = v
	}
	for k, v := range s.counts {
		snap.Counts[k] = v
	}
	s.mu.RUnlock()
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return s.store.Put(ctx, internaldb.BucketReputation, trustCacheKey, raw)
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
