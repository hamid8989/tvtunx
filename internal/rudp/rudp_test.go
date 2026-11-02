package rudp

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// TestRUDPEchoIntegrity sends a large payload client->server->client and checks
// that every byte arrives, in order, over the reliable-UDP transport.
func TestRUDPEchoIntegrity(t *testing.T) {
	ln, err := Listen("127.0.0.1:0", Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn) // echo
	}()

	c, err := Dial(ln.Addr().String(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	msg := make([]byte, 512*1024) // 512 KB
	rand.Read(msg)

	go func() {
		c.Write(msg)
	}()

	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload mismatch over rudp")
	}
}

// TestRUDPBidirectional runs independent streams both directions at once.
func TestRUDPBidirectional(t *testing.T) {
	ln, err := Listen("127.0.0.1:0", Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvMsg := bytes.Repeat([]byte("SERVER-"), 20000)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go conn.Write(srvMsg)
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()

	c, err := Dial(ln.Addr().String(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	cliMsg := bytes.Repeat([]byte("CLIENT-"), 20000)
	go c.Write(cliMsg)

	got := make([]byte, len(srvMsg))
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read server stream: %v", err)
	}
	if !bytes.Equal(got, srvMsg) {
		t.Fatalf("server->client mismatch")
	}
}
