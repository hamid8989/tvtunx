package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/local/tvtunx/internal/tcpcarrier"
)

// startEchoTCP starts a loopback TCP echo server and returns its address.
func startEchoTCP(t *testing.T) string {
	t.Helper()
	ol, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ol.Close() })
	go func() {
		for {
			c, err := ol.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return ol.Addr().String()
}

// roundTrip dials the relay port and checks a payload echoes back through the
// full tunnel.
func roundTrip(t *testing.T, relayPort int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("dual-stack-roundtrip!"), 1000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back through tunnel: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload mismatch through dual-stack tunnel")
	}
}

func freeRelayPort(t *testing.T) int {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// TestDualStackTCPForced runs the full relay->exit stack with the exit in its
// normal dual-stack mode (reality-udp UDP + TCP on the same port) and the relay
// pinned to -net tcp, proving the TCP carrier path carries real data end to end.
func TestDualStackTCPForced(t *testing.T) {
	echo := startEchoTCP(t)
	psk := []byte("dualstack-tcp-psk-dualstack-tcp0")

	// Reserve a UDP port for the exit; RunServer binds both UDP and TCP on it.
	uaddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	probe, _ := net.ListenUDP("udp", uaddr)
	exitAddr := probe.LocalAddr().String()
	probe.Close()

	go func() {
		_ = RunServer(ServerConfig{PSK: psk, Transport: TransportRealityUDP, ListenAddr: exitAddr})
	}()
	time.Sleep(300 * time.Millisecond)

	relayPort := freeRelayPort(t)
	go func() {
		_ = RunClient(ClientConfig{
			ServerAddr: exitAddr,
			PSK:        psk,
			Transport:  TransportRealityUDP,
			SNI:        "www.cloudflare.com",
			Net:        "tcp", // force the TCP carrier
			Forwards:   []Forward{{ListenPort: relayPort, Dest: echo, Proto: "tcp"}},
		})
	}()
	time.Sleep(700 * time.Millisecond)
	roundTrip(t, relayPort)
}

// TestAutoFallbackToTCPWhenUDPBlocked simulates a network that drops UDP: the
// exit serves ONLY the TCP carrier (no UDP listener on the port). A relay in the
// default -net auto mode must have its UDP carrier fail and automatically fall
// back to TCP, still carrying data end to end.
func TestAutoFallbackToTCPWhenUDPBlocked(t *testing.T) {
	echo := startEchoTCP(t)
	psk := []byte("dualstack-auto-psk-dualstackauto0")

	scfg := ServerConfig{PSK: psk, Transport: TransportRealityUDP, SNI: "www.cloudflare.com"}
	tl, err := tcpcarrier.Listen("127.0.0.1:0", tcpcarrier.Config{PSK: psk, SNICN: scfg.SNI})
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	exitAddr := tl.Addr().String() // TCP listener only; nothing answers on UDP here

	errc := make(chan error, 1)
	go acceptInto(tl, scfg, errc)

	// Fresh preference map for this exit addr is implicit (never connected before).
	relayPort := freeRelayPort(t)
	go func() {
		_ = RunClient(ClientConfig{
			ServerAddr: exitAddr,
			PSK:        psk,
			Transport:  TransportRealityUDP,
			SNI:        "www.cloudflare.com",
			Net:        "auto", // UDP will be tried first, must fall back to TCP
			Forwards:   []Forward{{ListenPort: relayPort, Dest: echo, Proto: "tcp"}},
		})
	}()
	time.Sleep(900 * time.Millisecond)
	roundTrip(t, relayPort)

	// Confirm the pool actually settled on TCP for this exit.
	if v, ok := pathPref.Load(exitAddr); !ok || v.(string) != "tcp" {
		t.Fatalf("expected auto mode to remember tcp for %s, got %v (ok=%v)", exitAddr, v, ok)
	}
}
