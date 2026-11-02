package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// TestRealityUDPEndToEnd runs the full tunnel over the reality-udp transport
// (QUIC masquerade handshake + reliable-UDP data), proving a real payload makes
// a round trip through the complete relay->exit stack.
func TestRealityUDPEndToEnd(t *testing.T) {
	ol, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ol.Close()
	go func() {
		for {
			c, err := ol.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	psk := []byte("reality-udp-e2e-psk-reality-udp0")

	uaddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	probe, _ := net.ListenUDP("udp", uaddr)
	exitAddr := probe.LocalAddr().String()
	probe.Close()

	go func() {
		_ = RunServer(ServerConfig{PSK: psk, Transport: TransportRealityUDP, ListenAddr: exitAddr})
	}()
	time.Sleep(300 * time.Millisecond)

	relayLn, _ := net.Listen("tcp", "127.0.0.1:0")
	relayPort := relayLn.Addr().(*net.TCPAddr).Port
	relayLn.Close()

	go func() {
		_ = RunClient(ClientConfig{
			ServerAddr: exitAddr,
			PSK:        psk,
			Transport:  TransportRealityUDP,
			SNI:        "www.cloudflare.com",
			Forwards:   []Forward{{ListenPort: relayPort, Dest: ol.Addr().String(), Proto: "tcp"}},
		})
	}()
	time.Sleep(600 * time.Millisecond)

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("reality-udp-roundtrip!"), 1000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back through reality-udp tunnel: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload mismatch through reality-udp transport")
	}
}
