package node

import (
	"sync"
	"testing"
)

func TestNodeEventBufferRecordAndPoll(t *testing.T) {
	buffer := newNodeEventBuffer()
	buffer.record("security", "spoofing_attempt", "peer-a", "invalid signature")
	buffer.record("mesh_event", "banned", "peer-b", "peer banned by hub")

	events, latestSeq := buffer.poll(0)
	if latestSeq != 2 {
		t.Fatalf("latestSeq = %d, want 2", latestSeq)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].Seq != 1 || events[0].Type != "spoofing_attempt" || events[0].PeerID != "peer-a" {
		t.Fatalf("unexpected first event: %+v", events[0])
	}
	if events[0].Timestamp == 0 {
		t.Fatal("timestamp not set")
	}
}

func TestNodeEventBufferCursor(t *testing.T) {
	buffer := newNodeEventBuffer()
	for i := 0; i < 5; i++ {
		buffer.record("security", "stale_event", "peer-a", "stale")
	}

	events, latestSeq := buffer.poll(3)
	if latestSeq != 5 {
		t.Fatalf("latestSeq = %d, want 5", latestSeq)
	}
	if len(events) != 2 || events[0].Seq != 4 || events[1].Seq != 5 {
		t.Fatalf("unexpected events after cursor 3: %+v", events)
	}

	// Re-reads are idempotent.
	again, _ := buffer.poll(3)
	if len(again) != 2 {
		t.Fatalf("re-read returned %d events, want 2", len(again))
	}
}

func TestNodeEventBufferWrap(t *testing.T) {
	buffer := newNodeEventBuffer()
	for i := 0; i < 1500; i++ {
		buffer.record("security", "rate_limit_drop", "peer-a", "dropped")
	}

	events, latestSeq := buffer.poll(0)
	if latestSeq != 1500 {
		t.Fatalf("latestSeq = %d, want 1500", latestSeq)
	}
	if len(events) != 1000 {
		t.Fatalf("len(events) = %d, want 1000", len(events))
	}
	if events[0].Seq != 501 || events[999].Seq != 1500 {
		t.Fatalf("wrap kept wrong window: first=%d last=%d", events[0].Seq, events[999].Seq)
	}
}

func TestNodeEventBufferConcurrent(t *testing.T) {
	buffer := newNodeEventBuffer()
	var waitGroup sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for i := 0; i < 200; i++ {
				buffer.record("security", "rate_limit_drop", "peer-a", "dropped")
				buffer.poll(0)
			}
		}()
	}
	waitGroup.Wait()

	_, latestSeq := buffer.poll(0)
	if latestSeq != 1600 {
		t.Fatalf("latestSeq = %d, want 1600", latestSeq)
	}
}
