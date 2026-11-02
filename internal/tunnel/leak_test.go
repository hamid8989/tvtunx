package tunnel

import (
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestNoGoroutineLeak opens and closes many short connections (like a client
// repeatedly probing / testing the config) and checks goroutines don't pile up.
// A per-connection goroutine leak was what left data stuck in Send-Q.
func TestNoGoroutineLeak(t *testing.T) {
	if os.Getenv("TV_LEAK") == "" {
		t.Skip("set TV_LEAK=1 to run")
	}
	origin := func(c net.Conn) {
		// Read a bit, reply a bit, close — like a quick handshake attempt.
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("hi"))
		c.Close()
	}
	addr, stop := startStack(t, origin)
	defer stop()

	// Warm up, then measure baseline.
	doConn := func() {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("hello"))
		_, _ = io.Copy(io.Discard, c)
		c.Close()
	}
	for i := 0; i < 20; i++ {
		doConn()
	}
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	base := runtime.NumGoroutine()

	// Hammer 300 short connections.
	for i := 0; i < 300; i++ {
		doConn()
	}
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	// Allow some slack, but a leak would add ~2 goroutines per connection.
	if after > base+40 {
		t.Fatalf("goroutine leak: baseline %d, after 300 conns %d (delta %d)", base, after, after-base)
	}
	t.Logf("no leak: baseline %d, after 300 short conns %d", base, after)
}
