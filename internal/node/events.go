package node

import (
	"sync"
	"time"
)

const nodeEventBufferSize = 1000

// NodeEvent is one verified observation recorded by the node.
type NodeEvent struct {
	Seq       uint64 `json:"seq"`
	Timestamp int64  `json:"timestamp"`
	Category  string `json:"category"`
	Type      string `json:"type"`
	PeerID    string `json:"peer_id,omitempty"`
	Message   string `json:"message,omitempty"`
}

type nodeEventBuffer struct {
	mu      sync.Mutex
	entries []NodeEvent
	nextSeq uint64
}

func newNodeEventBuffer() *nodeEventBuffer {
	return &nodeEventBuffer{nextSeq: 1}
}

var globalEventBuffer = newNodeEventBuffer()

// RecordNodeEvent appends an event to the global node event buffer.
func RecordNodeEvent(category, eventType, peerID, message string) {
	globalEventBuffer.record(category, eventType, peerID, message)
}

func (b *nodeEventBuffer) record(category, eventType, peerID, message string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries = append(b.entries, NodeEvent{
		Seq:       b.nextSeq,
		Timestamp: time.Now().UnixMilli(),
		Category:  category,
		Type:      eventType,
		PeerID:    peerID,
		Message:   message,
	})
	b.nextSeq++
	if len(b.entries) > nodeEventBufferSize {
		discarded := len(b.entries) - nodeEventBufferSize
		// Zero the trimmed prefix so its strings don't linger until the next reallocation.
		for i := range discarded {
			b.entries[i] = NodeEvent{}
		}
		b.entries = b.entries[discarded:]
	}
}

// poll returns events with seq > sinceSeq, oldest first, plus the latest seq.
func (b *nodeEventBuffer) poll(sinceSeq uint64) ([]NodeEvent, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	events := []NodeEvent{}
	for _, event := range b.entries {
		if event.Seq > sinceSeq {
			events = append(events, event)
		}
	}
	return events, b.nextSeq - 1
}
