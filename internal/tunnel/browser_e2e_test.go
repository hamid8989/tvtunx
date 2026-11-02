package tunnel

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/local/tvtunx/internal/browser"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestBrowserTransportEndToEnd runs the whole tunnel over the browser transport
// (real HTTP/3 duplex), with a self-signed cert in place of Let's Encrypt. The
// exit side is wired like runBrowserServer but without ACME; the relay side goes
// through the normal RunClient -> dialCarrier(browser) path.
func TestBrowserTransportEndToEnd(t *testing.T) {
	browserInsecureTLS = true
	defer func() { browserInsecureTLS = false }()

	// TCP echo origin behind the exit.
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

	psk := []byte("browser-e2e-psk-browser-e2e-psk0")

	// Exit: browser.Listen with a self-signed cert + serveTunnel per carrier.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	bl := browser.Listen(pc, tlsConf, psk)
	defer bl.Close()
	scfg := ServerConfig{PSK: psk, Transport: TransportBrowser, Domain: "localhost"}
	go func() {
		for {
			conn, err := bl.Accept()
			if err != nil {
				return
			}
			go serveTunnel(conn, scfg)
		}
	}()

	relayLn, _ := net.Listen("tcp", "127.0.0.1:0")
	relayPort := relayLn.Addr().(*net.TCPAddr).Port
	relayLn.Close()

	go func() {
		_ = RunClient(ClientConfig{
			ServerAddr: bl.Addr().String(),
			PSK:        psk,
			Transport:  TransportBrowser,
			Domain:     "localhost",
			Label:      "t", // exercise the PSK-rotating-subdomain SNI path
			Forwards:   []Forward{{ListenPort: relayPort, Dest: ol.Addr().String(), Proto: "tcp"}},
		})
	}()
	time.Sleep(800 * time.Millisecond)

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("browser-tunnel-roundtrip!"), 800)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(12 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back through browser tunnel: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload mismatch through browser transport")
	}
}
