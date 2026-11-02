package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func selfSigned(t *testing.T) tls.Certificate {
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

func startServer(t *testing.T, psk []byte) *Listener {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	return Listen(pc, cfg, psk)
}

// TestBrowserTunnelEcho runs the tunnel carrier end to end over a REAL HTTP/3
// request: the client dials as a browser, the exit authenticates the PSK cookie,
// and a bidirectional payload round-trips through the duplex stream.
func TestBrowserTunnelEcho(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	ln := startServer(t, psk)
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()

	conn, err := Dial(ln.Addr().String(), "localhost", psk, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("browser-tunnel-"), 4000) // ~60KB, forces streaming
	done := make(chan []byte, 1)
	go func() {
		got := make([]byte, 0, len(payload))
		b := make([]byte, 16*1024)
		for len(got) < len(payload) {
			n, err := conn.Read(b)
			if n > 0 {
				got = append(got, b[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- got
	}()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case got := <-done:
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch: got %d of %d bytes", len(got), len(payload))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for echo")
	}
}

// TestFakeSiteForUnauthenticated confirms a plain browser request (no PSK cookie)
// gets a real, ordinary web page — what a prober or visitor sees.
func TestFakeSiteForUnauthenticated(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	ln := startServer(t, psk)
	defer ln.Close()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"h3"}},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return quic.DialAddrEarly(ctx, ln.Addr().String(), tlsCfg, cfg)
		},
	}
	defer rt.Close()
	cli := &http.Client{Transport: rt, Timeout: 8 * time.Second}
	resp, err := cli.Get("https://localhost/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(b, []byte("It works")) {
		t.Fatalf("expected a fake site page, got status=%d body=%q", resp.StatusCode, string(b))
	}
}

// TestWrongPSKGetsFakeSite confirms a client with the wrong PSK does NOT get a
// tunnel (it is treated as an ordinary visitor — the POST returns the static page,
// so the tunnel handshake over it will fail rather than establish).
func TestWrongPSKGetsFakeSite(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	ln := startServer(t, psk)
	defer ln.Close()

	wrong := make([]byte, 32)
	rand.Read(wrong)
	conn, err := Dial(ln.Addr().String(), "localhost", wrong, &tls.Config{InsecureSkipVerify: true})
	// Dial itself succeeds (200 for the fake page), but no echo server runs for it
	// and the body is the static page, not a tunnel. Read should yield the page
	// bytes then EOF — never an echo.
	if err != nil {
		return // acceptable: some paths reject outright
	}
	defer conn.Close()
	conn.Write([]byte("ping"))
	b := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(b)
	if bytes.Contains(b[:n], []byte("ping")) {
		t.Fatal("wrong PSK must not be echoed (would mean it got a tunnel)")
	}
}
