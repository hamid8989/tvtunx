package handshake

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// pipeConn gives us two connected real TCP endpoints (buffered, unlike
// net.Pipe, so a one-sided write during a rejected handshake does not deadlock
// — which also matches the real deployment).
func pipeConn() (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	r := <-ch
	if r.err != nil {
		panic(r.err)
	}
	return client, r.c
}

func TestHandshakeSuccess(t *testing.T) {
	psk := []byte("correct-horse-battery-staple-xxxx")
	c, s := pipeConn()
	defer c.Close()
	defer s.Close()

	var sk, ck *Keys
	var serr, cerr error
	done := make(chan struct{})
	go func() { sk, serr = Server(s, psk); close(done) }()
	ck, cerr = Client(c, psk)
	<-done

	if cerr != nil || serr != nil {
		t.Fatalf("handshake errors: client=%v server=%v", cerr, serr)
	}
	// Client send key must equal server recv key and vice-versa.
	if !bytes.Equal(ck.SendKey, sk.RecvKey) || !bytes.Equal(ck.RecvKey, sk.SendKey) {
		t.Fatal("directional keys do not match across endpoints")
	}
	if ck.SendLenKey != sk.RecvLenKey || ck.RecvLenKey != sk.SendLenKey {
		t.Fatal("length-mask keys do not match")
	}
}

// TestProbeResistance: a client with the WRONG psk must get no usable reply,
// and the server must return ErrReject (caller then stays silent).
func TestProbeResistance(t *testing.T) {
	good := []byte("the-real-pre-shared-key-000000000")
	bad := []byte("an-active-prober-guessing-wrongly")

	c, s := pipeConn()
	defer c.Close()
	defer s.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := Server(s, good)
		serverErr <- err
	}()

	// Prober sends a wrong-PSK opening message, then watches for any reply.
	// Run it in a goroutine: a correct server never replies, so a synchronous
	// Client() would block forever (which is itself the desired behavior).
	go func() { _, _ = Client(c, bad) }()
	select {
	case err := <-serverErr:
		if err != ErrReject {
			t.Fatalf("expected ErrReject for bad PSK, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not decide within timeout")
	}

	// Confirm the server wrote nothing back to the prober.
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if n > 0 {
		t.Fatalf("server leaked %d reply bytes to a bad-PSK prober: %x", n, buf[:n])
	}
	if err == nil {
		t.Fatal("expected read timeout/EOF, got nil")
	}
	_ = io.EOF // silence import if unused across build tags
}
