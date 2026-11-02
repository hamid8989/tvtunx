// Package browser is the "browser" transport: the relay connects to the exit the
// way a real web browser connects to a real website — a genuine HTTP/3 (QUIC over
// UDP) request to a real domain, terminated by a real TLS certificate the exit
// actually holds (via Let's Encrypt). It is not an imitation of browser traffic;
// it IS browser traffic to a real site. A censor (passive or active) sees an
// ordinary HTTPS/H3 visit to a working website with a valid certificate, because
// that is exactly what it is.
//
// How the tunnel rides inside it: our client sends one long-lived HTTP/3 request
// to a secret path, authenticated by a PSK token carried in a cookie (so it is
// invisible inside the real TLS). The exit streams the request body (client->exit)
// and the response body (exit->client) concurrently, giving a full-duplex byte
// pipe — a net.Conn — over which the normal tunnel stack (handshake -> frame ->
// mux) runs unchanged. Any request WITHOUT the valid token gets a small, real,
// static web page instead, so a prober or a curious visitor just sees a website.
//
// UDP by design: HTTP/3 runs over QUIC over UDP, so this keeps the loss-tolerance
// that TCP transports lack (no TCP-over-TCP meltdown), while looking like exactly
// what modern browsers already do.
package browser

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ───────────────────────── PSK-rotating subdomains ─────────────────────────
//
// To defeat SNI-string blocklists, both ends derive a fresh hostname per day from
// the PSK, under a dedicated wildcard label the user owns (e.g. *.t.example.com):
//
//	<hmac(psk, domain,label,day)>.t.example.com
//
// A censor sees an ever-changing hostname that always resolves (wildcard A record)
// and always presents a valid certificate (per-name Let's Encrypt via HTTP-01), so
// no single SNI string can be blocked, and only a holder of the PSK knows which
// name is "ours". Rotation is daily, which keeps certificate issuance well under
// Let's Encrypt's rate limits (≈ one new name per day).

// RotatingName returns the PSK-derived hostname for the given time's day bucket.
func RotatingName(domain, label string, psk []byte, when time.Time) string {
	bucket := when.UTC().Unix() / 86400
	m := hmac.New(sha256.New, psk)
	fmt.Fprintf(m, "tvtunx/v1 rotating-subdomain|%s|%s|%d", domain, label, bucket)
	return hex.EncodeToString(m.Sum(nil)[:6]) + "." + label + "." + domain
}

// ValidRotatingName reports whether name is a PSK-valid rotating hostname for
// today or yesterday (the small window the exit will issue certificates for).
func ValidRotatingName(name, domain, label string, psk []byte, now time.Time) bool {
	for _, off := range []time.Duration{0, -24 * time.Hour} {
		if hmac.Equal([]byte(name), []byte(RotatingName(domain, label, psk, now.Add(off)))) {
			return true
		}
	}
	return false
}

const authCookie = "__Secure-sid" // looks like an ordinary session cookie

// authToken is a PSK-derived token, sent inside the real TLS session (a cookie),
// so only the exit can tell our client from a real browser. It stays confidential
// on the wire because the whole H3 request is encrypted under the real cert.
func authToken(psk []byte) string {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("tvtunx/v1 browser transport auth"))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// ───────────────────────── duplex net.Conn over one H3 request ─────────────────────────

type rwConn struct {
	r       io.Reader
	w       io.Writer
	flush   func()
	closeFn func()
	once    sync.Once
	done    chan struct{}
}

func (c *rwConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *rwConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if c.flush != nil {
		c.flush()
	}
	return n, err
}
func (c *rwConn) Close() error {
	c.once.Do(func() {
		if c.closeFn != nil {
			c.closeFn()
		}
		close(c.done)
	})
	return nil
}
func (c *rwConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *rwConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *rwConn) SetDeadline(t time.Time) error      { return nil }
func (c *rwConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *rwConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "h3" }
func (dummyAddr) String() string  { return "browser" }

// ───────────────────────── server (exit) ─────────────────────────

// Listener accepts browser-transport tunnel connections over HTTP/3.
type Listener struct {
	pc     net.PacketConn
	srv    *http3.Server
	psk    []byte
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once
}

// Listen binds a UDP socket and serves HTTP/3 on it with the given TLS config
// (which must carry a real certificate for the exit's domain, e.g. from autocert).
// Authenticated requests become tunnel carriers; everything else gets a static
// page. Pass a bound net.PacketConn (so the caller controls the UDP port).
func Listen(pc net.PacketConn, tlsConf *tls.Config, psk []byte) *Listener {
	l := &Listener{
		pc:     pc,
		psk:    psk,
		accept: make(chan net.Conn, 16),
		closed: make(chan struct{}),
	}
	tc := tlsConf.Clone()
	tc.NextProtos = []string{"h3"}
	l.srv = &http3.Server{
		TLSConfig: tc,
		Handler:   http.HandlerFunc(l.handle),
	}
	go l.srv.Serve(pc)
	return l
}

func (l *Listener) handle(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(authCookie)
	if err != nil || !tokenOK(ck.Value, l.psk) {
		serveFakeSite(w)
		return
	}
	// Authenticated: send 200 headers now so the client's request returns, then
	// run a full-duplex pipe over this one H3 stream.
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.Flush()
	conn := &rwConn{
		r:     r.Body,
		w:     w,
		flush: func() { rc.Flush() },
		done:  make(chan struct{}),
	}
	select {
	case l.accept <- conn:
	case <-l.closed:
		return
	}
	<-conn.done // keep the H3 stream (and this handler) alive until the tunnel closes
}

func tokenOK(got string, psk []byte) bool {
	return hmac.Equal([]byte(got), []byte(authToken(psk)))
}

// Accept returns the next authenticated tunnel carrier.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, errors.New("browser: listener closed")
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	_ = l.srv.Close()
	return l.pc.Close()
}

func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

// serveFakeSite returns a small, ordinary-looking web page to non-authenticated
// visitors (probers, scanners, a browser that stumbles on the domain).
func serveFakeSite(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fakePage)
}

const fakePage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>body{font-family:system-ui,sans-serif;margin:3rem auto;max-width:40rem;padding:0 1rem;color:#222}</style>
</head><body>
<h1>It works!</h1>
<p>This site is running normally. If you are the administrator, your service is online.</p>
</body></html>`

// ───────────────────────── client (relay) ─────────────────────────

// Dial connects to the exit as a browser would: a real HTTP/3 request to `domain`
// (verified against its real certificate), pinned to serverAddr (the exit's
// UDP host:port). It returns a full-duplex net.Conn carrying the tunnel. tlsConf
// may be nil (then the real cert of `domain` is verified normally).
func Dial(serverAddr, domain string, psk []byte, tlsConf *tls.Config) (net.Conn, error) {
	tc := tlsConf
	if tc == nil {
		tc = &tls.Config{}
	} else {
		tc = tc.Clone()
	}
	tc.ServerName = domain
	tc.NextProtos = []string{"h3"}

	rt := &http3.Transport{
		TLSClientConfig: tc,
		// Pin the QUIC connection to the exit's address while keeping SNI = domain,
		// so we connect to the exit's IP but present (and verify) the real domain.
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return quic.DialAddrEarly(ctx, serverAddr, tlsCfg, cfg)
		},
	}

	pr, pw := io.Pipe() // client -> exit body
	req, err := http.NewRequest(http.MethodPost, "https://"+domain+"/", pr)
	if err != nil {
		rt.Close()
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
	req.AddCookie(&http.Cookie{Name: authCookie, Value: authToken(psk)})

	resp, err := rt.RoundTrip(req)
	if err != nil {
		pw.Close()
		rt.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		rt.Close()
		return nil, errors.New("browser: exit did not accept the tunnel request")
	}
	return &rwConn{
		r:       resp.Body,
		w:       pw,
		closeFn: func() { pw.Close(); resp.Body.Close(); rt.Close() },
		done:    make(chan struct{}),
	}, nil
}
