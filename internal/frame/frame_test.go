package frame

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/local/tvtunx/internal/obfs"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c, <-ch
}

// TestRoundTrip pushes padded records both ways and checks payloads survive.
func TestRoundTrip(t *testing.T) {
	ka := make([]byte, 32)
	kb := make([]byte, 32)
	rand.Read(ka)
	rand.Read(kb)
	var la, lb [8]byte
	rand.Read(la[:])
	rand.Read(lb[:])

	raw1, raw2 := tcpPair(t)
	// endpoint A: send=ka recv=kb, lenSend=la lenRecv=lb
	a, err := NewConn(raw1, ka, kb, la, lb)
	if err != nil {
		t.Fatal(err)
	}
	// endpoint B mirrors.
	b, err := NewConn(raw2, kb, ka, lb, la)
	if err != nil {
		t.Fatal(err)
	}

	msgs := [][]byte{[]byte("hello"), bytes.Repeat([]byte("Z"), 9000), []byte("")}
	go func() {
		for _, m := range msgs {
			body, _ := obfs.Wrap(m, 300)
			if err := a.WriteRecord(body); err != nil {
				return
			}
		}
	}()
	for i, want := range msgs {
		rec, err := b.ReadRecord()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		got, err := obfs.Unwrap(rec)
		if err != nil {
			t.Fatalf("unwrap %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("msg %d mismatch: got %d bytes want %d", i, len(got), len(want))
		}
	}
}

// TestNoFixedPrefix: the first 32 bytes of two independent record streams must
// differ (keys/counters differ), i.e. no constant magic header leaks.
func TestNoFixedPrefix(t *testing.T) {
	first := func() []byte {
		ka := make([]byte, 32)
		kb := make([]byte, 32)
		rand.Read(ka)
		rand.Read(kb)
		var la, lb [8]byte
		rand.Read(la[:])
		rand.Read(lb[:])
		raw1, raw2 := tcpPair(t)
		a, _ := NewConn(raw1, ka, kb, la, lb)
		b, _ := NewConn(raw2, kb, ka, lb, la)
		body, _ := obfs.Wrap([]byte("GET / HTTP/1.1"), 50)
		go a.WriteRecord(body)
		hdr := make([]byte, 16)
		io.ReadFull(raw2FromConn(b), hdr)
		return hdr
	}
	x := first()
	y := first()
	if bytes.Equal(x, y) {
		t.Fatalf("two streams share an identical 16-byte prefix: %x", x)
	}
}

// raw2FromConn exposes the underlying conn for the prefix test.
func raw2FromConn(c *Conn) net.Conn { return c.raw.(net.Conn) }
