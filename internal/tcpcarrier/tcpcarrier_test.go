package tcpcarrier

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestKnockRoundTrip proves a correct PSK completes the TLS+knock handshake and
// carries bytes, and that a wrong PSK is rejected (the server stays silent).
func TestKnockRoundTrip(t *testing.T) {
	psk := []byte("tcpcarrier-unit-psk-0123456789ab")
	l, err := Listen("127.0.0.1:0", Config{PSK: psk, SNICN: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Echo server over accepted carriers.
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	// Correct PSK: handshake + data round trip.
	c, err := Dial(l.Addr().String(), DialConfig{PSK: psk, SNI: "www.example.com"})
	if err != nil {
		t.Fatalf("Dial with correct PSK: %v", err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("tls-knock-roundtrip!"), 200)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload mismatch over TCP carrier")
	}

	// Wrong PSK: the knock fails and the server drops the connection silently, so
	// Dial must return an error rather than yielding a usable carrier.
	if _, err := Dial(l.Addr().String(), DialConfig{PSK: []byte("wrong-psk-wrong-psk-wrong-psk-00"), SNI: "www.example.com"}); err == nil {
		t.Fatal("expected Dial with wrong PSK to fail")
	}
}
