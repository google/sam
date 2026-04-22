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
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/event"

	samnet "sam/pkg/net"
)

const proxyWatchHeartbeatInterval = 15 * time.Second

type inventoryWatchManager struct {
	federation string
	sub        event.Subscription

	mu       sync.Mutex
	nextID   uint64
	watchers map[uint64]chan samnet.AgentWatchEvent
	closed   bool
}

func newInventoryWatchManager(node samnet.Node, federation string) (*inventoryWatchManager, error) {
	sub, err := node.Host().EventBus().Subscribe(new(samnet.AgentWatchEvent))
	if err != nil {
		return nil, fmt.Errorf("subscribing to agent watch events: %w", err)
	}
	mgr := &inventoryWatchManager{
		federation: federation,
		sub:        sub,
		watchers:   map[uint64]chan samnet.AgentWatchEvent{},
	}
	go mgr.run()
	return mgr, nil
}

func (m *inventoryWatchManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	watchers := m.watchers
	m.watchers = map[uint64]chan samnet.AgentWatchEvent{}
	m.mu.Unlock()
	for id, ch := range watchers {
		close(ch)
		delete(watchers, id)
	}
	return m.sub.Close()
}

func (m *inventoryWatchManager) run() {
	for evt := range m.sub.Out() {
		switch agentEvent := evt.(type) {
		case samnet.AgentWatchEvent:
			m.broadcast(agentEvent)
		case *samnet.AgentWatchEvent:
			if agentEvent != nil {
				m.broadcast(*agentEvent)
			}
		}
	}
}

func (m *inventoryWatchManager) register() (uint64, <-chan samnet.AgentWatchEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextID
	m.nextID++
	ch := make(chan samnet.AgentWatchEvent, 32)
	m.watchers[id] = ch
	return id, ch
}

func (m *inventoryWatchManager) unregister(id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.watchers[id]; ok {
		delete(m.watchers, id)
		close(ch)
	}
}

func (m *inventoryWatchManager) broadcast(evt samnet.AgentWatchEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ch := range m.watchers {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (m *inventoryWatchManager) ServeInventoryWatch(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	id, ch := m.register()
	defer m.unregister(id)

	if err := writeSSEHeartbeat(w); err != nil {
		return
	}
	flusher.Flush()

	records, _ := samnet.LoadCachedAgentRecords(m.federation)
	for _, record := range records {
		if err := writeSSEEvent(w, samnet.AgentWatchEvent{Type: samnet.AgentWatchEventAdded, PeerID: record.PeerID, Card: record.Card}); err != nil {
			return
		}
		flusher.Flush()
	}

	heartbeat := time.NewTicker(proxyWatchHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSEEvent(w, evt); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if err := writeSSEHeartbeat(w); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
func writeSSEEvent(w http.ResponseWriter, evt samnet.AgentWatchEvent) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\n", evt.Type); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	return nil
}

func writeSSEHeartbeat(w http.ResponseWriter) error {
	if _, err := fmt.Fprint(w, "event: HEARTBEAT\ndata: {}\n\n"); err != nil {
		return err
	}
	return nil
}
