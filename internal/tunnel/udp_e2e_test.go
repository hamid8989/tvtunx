package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// TestUDPTransportEndToEnd runs the full tunnel over the reliable-UDP carrier.
func TestUDPTransportEndToEnd(t *testing.T) {
	ol, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer ol.Close()
	go func() {
		for {
			c, err := ol.Accept()
			if err != nil { return }
			go func(c net.Conn){ defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	psk := []byte("udp-e2e-psk-udp-e2e-psk-00000000")
	// exit on a UDP port
	uaddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	probe, _ := net.ListenUDP("udp", uaddr)
	exitAddr := probe.LocalAddr().String()
	probe.Close()

	exitCfg := ServerConfig{PSK: psk, Transport: TransportUDP, ListenAddr: exitAddr}
	go func(){ _ = RunServer(exitCfg) }()
	time.Sleep(300 * time.Millisecond)

	relayLn, _ := net.Listen("tcp", "127.0.0.1:0")
	relayPort := relayLn.Addr().(*net.TCPAddr).Port
	relayLn.Close()

	cfg := ClientConfig{
		ServerAddr: exitAddr,
		PSK:        psk,
		Transport:  TransportUDP,
		Forwards:   []Forward{{ListenPort: relayPort, Dest: ol.Addr().String(), Proto: "tcp"}},
	}
	go func(){ _ = RunClient(cfg) }()
	time.Sleep(600 * time.Millisecond)

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort), 5*time.Second)
	if err != nil { t.Fatal(err) }
	defer c.Close()
	msg := bytes.Repeat([]byte("udp-tunnel-roundtrip!"), 700)
	if _, err := c.Write(msg); err != nil { t.Fatal(err) }
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil { t.Fatalf("read back through udp tunnel: %v", err) }
	if !bytes.Equal(got, msg) { t.Fatalf("payload mismatch through udp transport") }
}
