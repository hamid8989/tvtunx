package rudp

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestKeepaliveEmittedWhenIdle verifies that an otherwise-idle Conn still emits
// packets at roughly keepaliveInterval, which is what keeps the UDP path's NAT
// mapping alive and prevents the "works then disconnects" symptom.
func TestKeepaliveEmittedWhenIdle(t *testing.T) {
	old := keepaliveInterval
	keepaliveInterval = 50 * time.Millisecond
	defer func() { keepaliveInterval = old }()

	var sent int64
	c := NewConn(Config{IdleTimeout: time.Hour}, 1234, func(b []byte) error {
		atomic.AddInt64(&sent, 1)
		return nil
	})
	defer c.Close()

	// No data written, no packets injected: only keepalives should fire.
	time.Sleep(350 * time.Millisecond)
	n := atomic.LoadInt64(&sent)
	if n < 3 {
		t.Fatalf("expected periodic keepalives (>=3 in 350ms at 50ms), got %d", n)
	}
}

// TestNoIdleCloseWhilePeerKeepsAlive verifies a Conn is NOT idle-closed while the
// peer keeps sending (keepalives count as received traffic).
func TestNoIdleCloseWhilePeerKeepsAlive(t *testing.T) {
	old := keepaliveInterval
	keepaliveInterval = 20 * time.Millisecond
	defer func() { keepaliveInterval = old }()

	c := NewConn(Config{IdleTimeout: 120 * time.Millisecond}, 7, func(b []byte) error { return nil })
	defer c.Close()

	// Feed a keepalive-ish ACK from the "peer" every 30ms for ~300ms; the conn
	// must stay open the whole time (idle timeout is 120ms).
	stop := time.After(300 * time.Millisecond)
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			if c.isClosed() {
				t.Fatal("conn was idle-closed despite peer keepalives")
			}
			return
		case <-tick.C:
			c.Inject(encode(7, cmdAck, 1024, 0, 0, nil))
		}
	}
}
