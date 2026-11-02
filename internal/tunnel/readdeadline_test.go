package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/local/tvtunx/internal/frame"
	"github.com/local/tvtunx/internal/mux"
)

// TestStreamReadDeadline verifies a Read with a deadline returns ErrReadTimeout
// instead of blocking forever when no data arrives — the guard that stops the
// benchmark/diag from hanging on a stalled tunnel.
func TestStreamReadDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	key := make([]byte, 32)
	var lk [8]byte
	fcA, err := frame.NewConn(c1, key, key, lk, lk)
	if err != nil {
		t.Fatal(err)
	}
	fcB, err := frame.NewConn(c2, key, key, lk, lk)
	if err != nil {
		t.Fatal(err)
	}
	a := mux.New(fcA, true, 0, 0)
	b := mux.New(fcB, false, 0, 0)
	defer a.Close()
	defer b.Close()

	st, err := a.Open("nowhere", mux.KindTCP)
	if err != nil {
		t.Fatal(err)
	}
	// Accept it on the other end but never send anything back.
	go func() { _, _ = b.Accept() }()

	st.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	start := time.Now()
	n, rerr := st.Read(make([]byte, 16))
	el := time.Since(start)
	if rerr != mux.ErrReadTimeout {
		t.Fatalf("expected ErrReadTimeout, got n=%d err=%v", n, rerr)
	}
	if el < 200*time.Millisecond || el > 2*time.Second {
		t.Fatalf("deadline fired at %v, expected ~300ms", el)
	}
}
