// Package tcpcarrier is the TCP fallback carrier. It provides the same
// net.Conn contract as the UDP carriers (rudp / qmask / browser), so the inner
// tunnel stack (handshake -> frame -> mux) rides over it unchanged.
//
// Why a TCP carrier exists:
//
//	The UDP transports are the default because they avoid TCP-over-TCP meltdown
//	and tolerate loss. But some paths block or drop UDP entirely (a cloud
//	firewall that only allows TCP, or an ISP that silently discards outbound
//	UDP to a foreign IP). When that happens the UDP carrier's handshake never
//	gets a reply and the tunnel cannot come up at all. The TCP carrier is the
//	escape hatch: the exit listens on the SAME port over TCP as well, and the
//	relay automatically falls back to it when UDP does not answer (see the
//	auto path in internal/tunnel). A firewall that blocks only UDP — the common
//	case in Iran — therefore no longer stops the tunnel.
//
// Wire shape (camouflage + auth):
//
//	The carrier is a normal TLS client/server handshake, so on the wire it looks
//	like an ordinary HTTPS connection (ClientHello with a real SNI, then
//	application data). The TLS layer is only a disguise, NOT the authenticator:
//	the client skips certificate verification and both sides prove knowledge of
//	the PSK with a short HMAC knock immediately after the TLS handshake. A
//	scanner that completes TLS but cannot answer the knock is dropped in
//	silence, exactly like a TLS server with no service behind it.
//
//	    client -> server:  nonce(16) || HMAC(psk, "knock"   || nonce)(32)
//	    server -> client:              HMAC(psk, "confirm" || nonce)(32)
//
// After the knock the raw tls.Conn is handed up as the carrier; the tunnel's
// own PSK handshake then keys the encrypted frame/mux stack on top.
package tcpcarrier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	knockTimeout = 10 * time.Second
	dialTimeout  = 15 * time.Second
	nonceLen     = 16
	macLen       = 32
)

var (
	knockLabel   = []byte("tvtunx/v2 tcp-knock")
	confirmLabel = []byte("tvtunx/v2 tcp-confirm")
)

// authMAC is HMAC-SHA256(psk, label || nonce).
func authMAC(psk, label, nonce []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(label)
	m.Write(nonce)
	return m.Sum(nil)
}

// ───────────────────────────── client ─────────────────────────────

// DialConfig configures the client side of the TCP carrier.
type DialConfig struct {
	PSK []byte
	SNI string // TLS ServerName (ClientHello SNI); may be empty
}

// Dial connects to addr over TCP+TLS and performs the PSK knock. The returned
// net.Conn is the established TLS stream, ready for the tunnel's own handshake.
func Dial(addr string, cfg DialConfig) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	if t, ok := raw.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: true, // PSK knock is the authenticator, not the cert
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	_ = tc.SetDeadline(time.Now().Add(knockTimeout))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return nil, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		tc.Close()
		return nil, err
	}
	msg := make([]byte, 0, nonceLen+macLen)
	msg = append(msg, nonce...)
	msg = append(msg, authMAC(cfg.PSK, knockLabel, nonce)...)
	if _, err := tc.Write(msg); err != nil {
		tc.Close()
		return nil, err
	}

	resp := make([]byte, macLen)
	if _, err := io.ReadFull(tc, resp); err != nil {
		tc.Close()
		return nil, errors.New("tcpcarrier: no/short confirm (not a tvtunx exit, or UDP-only path)")
	}
	if !hmac.Equal(resp, authMAC(cfg.PSK, confirmLabel, nonce)) {
		tc.Close()
		return nil, errors.New("tcpcarrier: bad confirm (PSK mismatch)")
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

// ───────────────────────────── server ─────────────────────────────

// Config configures the server side of the TCP carrier.
type Config struct {
	PSK []byte
	// TLS supplies the server certificate (e.g. the browser transport's real
	// Let's Encrypt cert via GetCertificate). If nil, a self-signed certificate
	// is generated at startup with SNICN as its name — the client never verifies
	// it, so this is purely cosmetic for the TLS record on the wire.
	TLS   *tls.Config
	SNICN string
}

// Listener accepts TCP-carrier connections on one TCP socket.
type Listener struct {
	ln     net.Listener
	psk    []byte
	tlsCfg *tls.Config
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once
}

// Listen binds a TCP socket and serves the TLS + PSK-knock carrier.
func Listen(addr string, cfg Config) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsCfg := cfg.TLS
	if tlsCfg == nil {
		cert, err := selfSigned(cfg.SNICN)
		if err != nil {
			ln.Close()
			return nil, err
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}
	l := &Listener{
		ln:     ln,
		psk:    cfg.PSK,
		tlsCfg: tlsCfg,
		accept: make(chan net.Conn, 16),
		closed: make(chan struct{}),
	}
	go l.loop()
	return l, nil
}

func (l *Listener) loop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.serveHandshake(c)
	}
}

func (l *Listener) serveHandshake(raw net.Conn) {
	if t, ok := raw.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
	}
	tc := tls.Server(raw, l.tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(knockTimeout))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return
	}
	buf := make([]byte, nonceLen+macLen)
	if _, err := io.ReadFull(tc, buf); err != nil {
		tc.Close()
		return
	}
	nonce := buf[:nonceLen]
	if !hmac.Equal(buf[nonceLen:], authMAC(l.psk, knockLabel, nonce)) {
		// Scanner or wrong PSK: stay silent and drop, like a TLS endpoint with no
		// application service behind it. No error is written back.
		tc.Close()
		return
	}
	if _, err := tc.Write(authMAC(l.psk, confirmLabel, nonce)); err != nil {
		tc.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	select {
	case l.accept <- tc:
	case <-l.closed:
		tc.Close()
	}
}

// Accept returns the next authenticated TCP-carrier connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, errors.New("tcpcarrier: listener closed")
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.ln.Close()
}

func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// ───────────────────────────── self-signed cert ─────────────────────────────

// selfSigned builds a throwaway ECDSA certificate for cn. The client never
// verifies it (InsecureSkipVerify), so it only shapes the bytes of the TLS
// record — a ClientHello/Certificate exchange for a plausible name.
func selfSigned(cn string) (tls.Certificate, error) {
	if cn == "" {
		cn = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     []string{cn},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
