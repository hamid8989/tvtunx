package tunnel

import (
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestReturnPathSlowReader reproduces the production symptom: the exit streams
// a lot of data back while the local client reads slowly. If the relay's
// readLoop stalls (return path blocked), this hangs / times out.
func TestReturnPathSlowReader(t *testing.T) {
	if os.Getenv("TV_STALL") == "" {
		t.Skip("set TV_STALL=1 to run")
	}
	const total = 8 * 1024 * 1024 // 8MB streamed back
	origin := func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 1024)
		_, _ = c.Read(buf)
		data := make([]byte, 32*1024)
		sent := 0
		for sent < total {
			n, err := c.Write(data)
			if err != nil {
				return
			}
			sent += n
		}
	}
	addr, stop := startStack(t, origin)
	defer stop()

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GO"))

	// Slow reader: read in small chunks with a tiny delay, like a real app.
	got := 0
	buf := make([]byte, 16*1024)
	deadline := time.Now().Add(20 * time.Second)
	for got < total {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		got += n
		if n > 0 && got%(1024*1024) < 16*1024 {
			time.Sleep(2 * time.Millisecond) // simulate slow consumer
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("stalled after %d/%d bytes: %v", got, total, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %d/%d bytes (return path stalled)", got, total)
		}
	}
	if got < total {
		t.Fatalf("short: got %d want %d", got, total)
	}
	t.Logf("received all %d bytes through the return path", got)
}
