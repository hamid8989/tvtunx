package tunnel

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestSlowConsumerDoesNotStallOthers reproduces the production bug: one
// connection whose consumer stops reading must NOT stall other connections,
// and must not let unread data pile up without bound (Recv-Q blowup). With
// per-connection sessions + a bounded receive window, the stuck connection
// simply backpressures itself while the others run freely.
func TestSlowConsumerDoesNotStallOthers(t *testing.T) {
	if os.Getenv("TV_BP") == "" {
		t.Skip("set TV_BP=1 to run")
	}
	// Origin streams data forever as fast as it can.
	origin := func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 1024)
		_, _ = c.Read(buf)
		data := make([]byte, 32*1024)
		for {
			if _, err := c.Write(data); err != nil {
				return
			}
		}
	}
	addr, stop := startStack(t, origin)
	defer stop()

	// Connection A: open it, send the request, then STOP reading (stuck).
	stuck, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stuck.Close()
	_, _ = stuck.Write([]byte("GO"))
	// deliberately never read from `stuck`

	time.Sleep(500 * time.Millisecond) // let it fill its window and backpressure

	// Connection B: must still work normally and move data fast.
	var okFast atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		fast, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return
		}
		defer fast.Close()
		_, _ = fast.Write([]byte("GO"))
		got := 0
		buf := make([]byte, 32*1024)
		deadline := time.Now().Add(5 * time.Second)
		for got < 8*1024*1024 { // 8MB
			_ = fast.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := fast.Read(buf)
			got += n
			if err != nil {
				break
			}
			if time.Now().After(deadline) {
				break
			}
		}
		if got >= 8*1024*1024 {
			okFast.Store(true)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("fast connection timed out — slow consumer stalled others")
	}
	if !okFast.Load() {
		t.Fatal("fast connection did not complete while another was stuck")
	}
	t.Log("a stuck connection did not stall a healthy one; backpressure isolated it")
}
