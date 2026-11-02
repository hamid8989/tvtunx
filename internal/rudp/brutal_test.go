package rudp

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"testing"
	"time"
)

// TestBrutalCompensatesLoss wires two conns through a lossy link with a Brutal
// rate target set, transfers a payload, and verifies (a) it arrives intact and
// (b) the loss-compensation multiplier rose above 1 — i.e. the sender sped up to
// counter loss instead of backing off, the Hysteria-Brutal behaviour.
func TestBrutalCompensatesLoss(t *testing.T) {
	const conv = 0x5151abcd
	const lossP = 0.15
	old := rateCalcInterval
	rateCalcInterval = 100 * time.Millisecond // observe compensation within the transfer
	defer func() { rateCalcInterval = old }()
	cfg := Config{Conv: conv, TargetMbit: 50} // Brutal at 50 Mbit

	aOut := make(chan []byte, 8192)
	bOut := make(chan []byte, 8192)
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

	msg := make([]byte, 512*1024)
	rand.Read(msg)
	go func() { a.Write(msg) }()

	got := make([]byte, len(msg))
	b.SetReadDeadline(time.Now().Add(40 * time.Second))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read under loss with Brutal: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload corrupted")
	}
	a.mu.Lock()
	comp := a.rateComp
	a.mu.Unlock()
	t.Logf("512KB delivered through 15%% loss; Brutal rate compensation = %.2fx", comp)
	if comp <= 1.0 {
		t.Errorf("expected loss compensation > 1x under 15%% loss, got %.2fx", comp)
	}
}
