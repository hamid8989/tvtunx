package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// TestBidirectionalConcurrent mimics VLESS-style traffic: many connections,
// each sending and receiving continuously at the same time, all sharing the
// session pool. This is the case most likely to expose a write-side
// head-of-line stall (one slow stream blocking the shared write lock).
func TestBidirectionalConcurrent(t *testing.T) {
	if os.Getenv("TV_BIDI") == "" {
		t.Skip("set TV_BIDI=1 to run")
	}
	// Echo origin: reads a length-prefixed message, echoes it back, repeats.
	origin := func(c net.Conn) {
		defer c.Close()
		hdr := make([]byte, 4)
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr)
			body := make([]byte, n)
			if _, err := io.ReadFull(c, body); err != nil {
				return
			}
			if _, err := c.Write(hdr); err != nil {
				return
			}
			if _, err := c.Write(body); err != nil {
				return
			}
		}
	}
	addr, stop := startStack(t, origin)
	defer stop()

	const conns = 30
	const rounds = 50
	var wg sync.WaitGroup
	fail := make(chan error, conns)
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				fail <- err
				return
			}
			defer c.Close()
			payload := bytes.Repeat([]byte{byte(id)}, 4096)
			hdr := make([]byte, 4)
			binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
			rhdr := make([]byte, 4)
			rbody := make([]byte, len(payload))
			for r := 0; r < rounds; r++ {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(hdr); err != nil {
					fail <- err
					return
				}
				if _, err := c.Write(payload); err != nil {
					fail <- err
					return
				}
				if _, err := io.ReadFull(c, rhdr); err != nil {
					fail <- err
					return
				}
				if _, err := io.ReadFull(c, rbody); err != nil {
					fail <- err
					return
				}
				if !bytes.Equal(rbody, payload) {
					fail <- io.ErrUnexpectedEOF
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(fail)
	for e := range fail {
		t.Fatalf("bidi stream failed: %v", e)
	}
	t.Logf("%d concurrent bidirectional streams x %d rounds OK", conns, rounds)
}
