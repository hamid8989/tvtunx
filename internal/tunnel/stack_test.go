package tunnel

import (
	"net"
	"testing"
	"time"
)

// startStack spins up a full in-process tunnel over the reliable-UDP carrier:
// a TCP origin running `origin` per connection, an exit (RunServer) on a UDP
// port, and a relay (RunClient) forwarding a local TCP port to the origin via
// the exit. It returns the relay's local TCP address (dial this) and a stop
// function. Shared by the behavioural tests (backpressure, bidi, leak, stall).
func startStack(t *testing.T, origin func(net.Conn)) (string, func()) {
	t.Helper()

	ol, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ol.Accept()
			if err != nil {
				return
			}
			go origin(c)
		}
	}()

	psk := []byte("startstack-psk-startstack-psk-00")

	// Pick a free UDP port for the exit.
	uaddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	pc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		t.Fatal(err)
	}
	exitAddr := pc.LocalAddr().String()
	pc.Close()

	go func() {
		_ = RunServer(ServerConfig{PSK: psk, Transport: TransportUDP, ListenAddr: exitAddr})
	}()
	time.Sleep(300 * time.Millisecond)

	// Pick a free TCP port for the relay's local listener.
	rl, _ := net.Listen("tcp", "127.0.0.1:0")
	relayPort := rl.Addr().(*net.TCPAddr).Port
	rl.Close()

	go func() {
		_ = RunClient(ClientConfig{
			ServerAddr: exitAddr,
			PSK:        psk,
			Transport:  TransportUDP,
			Forwards:   []Forward{{ListenPort: relayPort, Dest: ol.Addr().String(), Proto: "tcp"}},
		})
	}()
	time.Sleep(600 * time.Millisecond)

	addr := net.JoinHostPort("127.0.0.1", itoa(relayPort))
	return addr, func() { ol.Close() }
}
