package qmask

import (
	"encoding/binary"
	"sync"
	"time"
)

// replayCache rejects a client Initial whose ClientHello random has already been
// seen within a time window. A passive prober that captures and replays a real
// client Initial toward the exit therefore gets no reply the second time, the
// same as any unauthenticated packet, so replay reveals nothing.
type replayCache struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[uint64]time.Time
	last   time.Time
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{window: window, seen: make(map[uint64]time.Time)}
}

// seenAndRecord returns true if this random was already recorded within the
// window; otherwise it records it and returns false.
func (r *replayCache) seenAndRecord(clientRandom []byte) bool {
	if len(clientRandom) < 8 {
		return true // malformed — treat as replay/garbage
	}
	k := binary.BigEndian.Uint64(clientRandom[:8])
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.last) > r.window {
		r.gc(now) // amortised cleanup
		r.last = now
	}
	if t, ok := r.seen[k]; ok && now.Sub(t) < r.window {
		return true
	}
	r.seen[k] = now
	return false
}

func (r *replayCache) gc(now time.Time) {
	for k, t := range r.seen {
		if now.Sub(t) >= r.window {
			delete(r.seen, k)
		}
	}
}
