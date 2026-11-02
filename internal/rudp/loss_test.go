package rudp

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"testing"
	"time"
)

// TestRUDPLossRecovery wires two conns through a lossy link (20% drop each way)
// and verifies the full payload still arrives intact — the behaviour that lets
// the tunnel survive a throttled, lossy path where plain TCP collapses.
func TestRUDPLossRecovery(t *testing.T) {
	const conv = 0x1234abcd
	const lossP = 0.20
	cfg := Config{Conv: conv, WindowSegs: 512}

	aOut := make(chan []byte, 4096)
	bOut := make(chan []byte, 4096)
	a := newConn(cfg, conv, func(p []byte) error {
		cp := append([]byte(nil), p...)
		select {
		case aOut <- cp:
		default:
		}
		return nil
	})
	b := newConn(cfg, conv, func(p []byte) error {
		cp := append([]byte(nil), p...)
		select {
		case bOut <- cp:
		default:
		}
		return nil
	})
	defer a.Close()
	defer b.Close()

	go func() {
		for p := range aOut {
			if mrand.Float64() >= lossP {
				select {
				case b.inbox <- p:
				case <-b.done:
				}
			}
		}
	}()
	go func() {
		for p := range bOut {
			if mrand.Float64() >= lossP {
				select {
				case a.inbox <- p:
				case <-a.done:
				}
			}
		}
	}()

	msg := make([]byte, 256*1024)
	rand.Read(msg)
	go func() { a.Write(msg) }()

	got := make([]byte, len(msg))
	b.SetReadDeadline(time.Now().Add(40 * time.Second))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read under loss: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload corrupted under loss")
	}
	t.Logf("256KB delivered intact through 20%% packet loss each way")
}
