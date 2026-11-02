package qmask

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestTransportLoopback runs the whole reality-udp path over a real UDP socket:
// masquerade handshake (QUIC Initial + auth), then a bidirectional bulk transfer
// over rudp with QUIC-1-RTT framing.
func TestTransportLoopback(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	cfg := Config{SNI: "www.google.com", PSK: psk}

	ln, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Echo server.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()

	conn, err := Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 512*1024)
	rand.Read(payload)

	var wg sync.WaitGroup
	wg.Add(1)
	var got []byte
	var rerr error
	go func() {
		defer wg.Done()
		got = make([]byte, 0, len(payload))
		b := make([]byte, 32*1024)
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		for len(got) < len(payload) {
			n, err := conn.Read(b)
			if n > 0 {
				got = append(got, b[:n]...)
			}
			if err != nil {
				rerr = err
				return
			}
		}
	}()

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wg.Wait()
	if rerr != nil {
		t.Fatalf("read: %v (got %d/%d)", rerr, len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}
}

// TestTransportWrongPSK confirms a client with the wrong PSK cannot complete the
// handshake (the exit stays silent, so Dial times out and fails).
func TestTransportWrongPSK(t *testing.T) {
	serverPSK := make([]byte, 32)
	rand.Read(serverPSK)
	clientPSK := make([]byte, 32)
	rand.Read(clientPSK)

	ln, err := Listen("127.0.0.1:0", Config{SNI: "example.com", PSK: serverPSK})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	start := time.Now()
	_, err = Dial(ln.Addr().String(), Config{SNI: "example.com", PSK: clientPSK})
	if err == nil {
		t.Fatal("Dial should fail with the wrong PSK")
	}
	// Should fail only after exhausting retries (the exit is silent), not instantly.
	if time.Since(start) < handshakeTimeout {
		t.Errorf("failed too fast (%v); expected silent-drop timeout", time.Since(start))
	}
}

var _ = net.IPv4len
