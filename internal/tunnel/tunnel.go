// Package tunnel wires the layers into a relay (client) and an exit (server)
// that perform raw TCP+UDP port-forwarding over the encrypted mux.
//
// Relay role (runs on the inner/restricted side):
//   - listens on one or more local ports, each TCP and UDP
//   - every inbound TCP connection becomes a KindTCP mux stream to the exit's
//     fixed destination for that port
//   - every inbound UDP flow (by source address) becomes a KindUDP mux stream
//
// Exit role (runs abroad):
//   - accepts tunnel connections, runs the probe-resistant handshake
//   - for each inbound stream, dials the fixed destination (TCP or UDP) and
//     relays bytes/datagrams
//
// The tunnel does not inspect or terminate any application protocol. Whatever
// the client speaks to the relay port (VLESS, VMESS, WireGuard, plain TCP/UDP)
// is forwarded verbatim to the destination behind the exit.
package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/local/tvtunx/internal/acmedns"
	"github.com/local/tvtunx/internal/browser"
	"github.com/local/tvtunx/internal/frame"
	"github.com/local/tvtunx/internal/handshake"
	"github.com/local/tvtunx/internal/mux"
	"github.com/local/tvtunx/internal/qmask"
	"github.com/local/tvtunx/internal/rudp"
	"github.com/local/tvtunx/internal/tcpcarrier"
)

const (
	defaultPadMax  = 512
	udpIdleTimeout = 60 * time.Second
	udpReadBuf     = 64 * 1024
	dialTimeout    = 15 * time.Second
)

// Forward maps a local relay port to a fixed destination behind the exit.
type Forward struct {
	ListenPort int    // port opened on the relay
	Dest       string // "host:port" the exit dials for this forward
	Proto      string // "tcp", "udp", or "both" (default both)
}

func (f Forward) wantTCP() bool { return f.Proto == "" || f.Proto == "both" || f.Proto == "tcp" }
func (f Forward) wantUDP() bool { return f.Proto == "" || f.Proto == "both" || f.Proto == "udp" }

// tune applies low-latency socket options to a TCP connection.
func tune(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true) // disable Nagle: lower latency for interactive flows
		_ = t.SetKeepAlive(true)
		_ = t.SetKeepAlivePeriod(30 * time.Second)
	}
}

// ───────────────────────────── Relay (client) ─────────────────────────────

type ClientConfig struct {
	ServerAddr string // exit host:port
	PSK        []byte
	PadMax     int
	Forwards   []Forward
	SNI        string // real site name shown in the reality-udp ClientHello
	Window     int    // per-stream flow-control window in bytes (0 = default)

	// Transport selects the carrier: "udp", "reality-udp" or "browser".
	Transport string

	// Domain is the real site name for the "browser" transport (the exit holds a
	// real certificate for it; the relay connects to it like a browser).
	Domain string
	// Label, when set (e.g. "t"), enables PSK-rotating subdomains under
	// *.<Label>.<Domain>: the connection hostname changes daily so no single SNI
	// string can be blocklisted. Empty = use Domain directly.
	Label string
	// DoH, when set to a DNS-over-HTTPS endpoint (e.g.
	// https://cloudflare-dns.com/dns-query), makes the relay resolve the exit's
	// hostname over encrypted DNS instead of connecting to a pinned IP — the
	// censor sees only DoH to a big resolver, not the hostname. Browser transport.
	DoH string

	// RotateSec, when > 0, retires each pooled connection after this many seconds
	// and replaces it with a fresh one, to counter ISP per-flow throttling that
	// ramps up over a connection's lifetime. 0 disables rotation.
	RotateSec int

	// PoolSize is the number of parallel tunnel connections to the exit (0 =
	// default). Raising it multiplies throughput when the ISP throttles each flow
	// independently.
	PoolSize int

	// UDPTargetMbit paces the UDP carrier to this rate (0 = unpaced,
	// window-limited). Used by both "udp" and "reality-udp".
	UDPTargetMbit int

	// Net selects which carrier network the relay uses:
	//   "auto" (default) — try the transport's UDP carrier first and, if it does
	//                       not answer (blocked/dropped UDP), fall back to TCP on
	//                       the same port. The winning path is remembered so later
	//                       sessions go straight to it.
	//   "udp"            — UDP carrier only (never fall back).
	//   "tcp"            — TCP carrier only (for paths that block UDP outright).
	// The exit always listens on BOTH, so a relay can pick either without any
	// server-side change.
	Net string
}

// defaultPoolSize is the number of persistent tunnel connections to the exit
// that ALL flows (TCP and UDP) multiplex over, when none is configured. It is
// kept smallish by default because opening very many connections to one foreign
// IP can itself get that IP's connection count flagged. But when the ISP
// throttles each FLOW (5-tuple) independently — the common case on a single
// foreign IP — more parallel connections multiply the aggregate throughput,
// since each flow is capped separately. So PoolSize is tunable: raise it to beat
// per-flow throttling, lower it if a high count triggers connection-count blocks.
const defaultPoolSize = 6

// maxUDPFlows caps concurrent UDP source flows so a flood of source ports can
// never grow the map without limit.
const maxUDPFlows = 2048

func RunClient(cfg ClientConfig) error {
	if len(cfg.Forwards) == 0 {
		return &simpleErr{"no forwards configured"}
	}
	ps := cfg.PoolSize
	if ps <= 0 {
		ps = defaultPoolSize
	}
	pool := NewSessionPool(cfg, ps)
	defer pool.Close()

	var wg sync.WaitGroup
	for _, f := range cfg.Forwards {
		f := f
		if f.wantTCP() {
			wg.Add(1)
			go func() { defer wg.Done(); relayTCP(pool, f) }()
		}
		if f.wantUDP() {
			wg.Add(1)
			go func() { defer wg.Done(); relayUDP(pool, f) }()
		}
	}
	wg.Wait()
	return nil
}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

func relayTCP(pool *SessionPool, f Forward) {
	ln, err := net.Listen("tcp", listenAddr(f.ListenPort))
	if err != nil {
		log.Printf("relay tcp :%d listen failed: %v", f.ListenPort, err)
		return
	}
	log.Printf("relay TCP :%d -> %s (via exit)", f.ListenPort, f.Dest)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tune(c)
		go handleTCPConn(pool, f, c)
	}
}

// handleTCPConn carries this connection as one stream multiplexed over the
// shared pool. Credit flow control keeps a slow stream from stalling others.
func handleTCPConn(pool *SessionPool, f Forward, c net.Conn) {
	defer c.Close()
	st, err := pool.OpenStream(f.Dest, mux.KindTCP)
	if err != nil {
		return
	}
	defer st.Close()
	pipeTCP(c, st)
}

// relayUDP forwards UDP. Each distinct client source address gets its own mux
// STREAM (not its own session — streams are cheap and share the pool, which is
// what keeps memory bounded). Flows are reaped on idle and the total is capped.
func relayUDP(pool *SessionPool, f Forward) {
	pc, err := net.ListenPacket("udp", listenAddr(f.ListenPort))
	if err != nil {
		log.Printf("relay udp :%d listen failed: %v", f.ListenPort, err)
		return
	}
	log.Printf("relay UDP :%d -> %s (via exit)", f.ListenPort, f.Dest)

	type flow struct {
		st     *mux.Stream
		lastNS atomic.Int64
	}
	var mu sync.Mutex
	flows := make(map[string]*flow)

	// Single idle reaper for ALL flows (one goroutine, not one per flow).
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()
			mu.Lock()
			for k, fl := range flows {
				if fl.lastNS.Load() < cutoff {
					fl.st.Close()
					delete(flows, k)
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, udpReadBuf)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		key := src.String()
		mu.Lock()
		fl := flows[key]
		if fl == nil {
			if len(flows) >= maxUDPFlows {
				mu.Unlock()
				continue // shed load rather than grow unbounded
			}
			st, oerr := pool.OpenStream(f.Dest, mux.KindUDP)
			if oerr != nil {
				mu.Unlock()
				continue
			}
			fl = &flow{st: st}
			flows[key] = fl
			// reply pump: datagrams from exit -> back to this client src
			go func(fl *flow, src net.Addr, key string) {
				for {
					d, rerr := fl.st.ReadDatagram()
					if rerr != nil {
						break
					}
					_, _ = pc.WriteTo(d, src)
				}
				mu.Lock()
				if flows[key] == fl {
					delete(flows, key)
				}
				mu.Unlock()
				fl.st.Close()
			}(fl, src, key)
		}
		fl.lastNS.Store(time.Now().UnixNano())
		st := fl.st
		mu.Unlock()
		_ = st.WriteDatagram(buf[:n])
	}
}

// pathPref remembers, per exit address, which carrier network last connected
// ("udp" or "tcp"), so that once auto-fallback has found a working path the
// pool's later sessions go straight to it instead of racing every time.
var pathPref sync.Map // serverAddr(string) -> path(string)

// dialSession dials one tunnel session honoring cfg.Net:
//   - "udp" / "tcp": that carrier only.
//   - "auto" (default/empty): try the remembered good path first; otherwise race
//     the UDP and TCP carriers and keep whichever completes the full handshake
//     first, so a blocked-UDP path transparently uses TCP without a long stall.
func dialSession(cfg ClientConfig) (*mux.Session, error) {
	switch strings.ToLower(cfg.Net) {
	case "udp":
		return dialSessionOn(cfg, "udp")
	case "tcp":
		return dialSessionOn(cfg, "tcp")
	}
	// auto: prefer the last known-good path, else race both.
	key := cfg.ServerAddr
	if v, ok := pathPref.Load(key); ok {
		if s, err := dialSessionOn(cfg, v.(string)); err == nil {
			return s, nil
		}
		pathPref.Delete(key) // the remembered path stopped working; re-discover
	}
	return dialSessionRace(cfg)
}

type dialResult struct {
	sess *mux.Session
	path string
	err  error
}

// dialSessionRace dials the UDP and TCP carriers concurrently and returns the
// first to fully connect, closing the loser. This is what lets a firewall that
// blocks only UDP (or only TCP) be bypassed automatically: the surviving
// protocol wins the race and is remembered for subsequent sessions.
func dialSessionRace(cfg ClientConfig) (*mux.Session, error) {
	ch := make(chan dialResult, 2)
	for _, p := range []string{"udp", "tcp"} {
		p := p
		go func() {
			s, err := dialSessionOn(cfg, p)
			ch <- dialResult{sess: s, path: p, err: err}
		}()
	}
	first := <-ch
	if first.err == nil {
		pathPref.Store(cfg.ServerAddr, first.path)
		go func() { // close the loser whenever it eventually finishes
			r := <-ch
			if r.sess != nil {
				r.sess.Close()
			}
		}()
		return first.sess, nil
	}
	second := <-ch
	if second.err == nil {
		pathPref.Store(cfg.ServerAddr, second.path)
		return second.sess, nil
	}
	return nil, &simpleErr{"both carriers failed — udp: " + first.err.Error() + "; tcp: " + second.err.Error()}
}

// dialSessionOn dials a specific carrier network ("udp" or "tcp") and runs the
// inner PSK handshake + frame + mux over it. The inner stack is identical for
// every transport and network, so the mux layer never knows which carrier it rode.
func dialSessionOn(cfg ClientConfig, path string) (*mux.Session, error) {
	var raw net.Conn
	var err error
	if path == "tcp" {
		raw, err = dialCarrierTCP(cfg)
	} else {
		raw, err = dialCarrierUDP(cfg)
	}
	if err != nil {
		return nil, err
	}
	// Bound the inner handshake. On a PSK/transport mismatch the exit passes the
	// connection through to the real SNI site (or never replies) — without a
	// deadline the read would block forever. A timeout turns that into a clear,
	// fast error instead of a hang (and lets the race abandon a dead path).
	_ = raw.SetDeadline(time.Now().Add(dialTimeout))
	keys, err := handshake.Client(raw, cfg.PSK)
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	fc, err := frame.NewConn(raw, keys.SendKey, keys.RecvKey, keys.SendLenKey, keys.RecvLenKey)
	if err != nil {
		raw.Close()
		return nil, err
	}
	pm := cfg.PadMax
	if pm == 0 {
		pm = defaultPadMax
	}
	return mux.New(fc, true, pm, cfg.Window), nil
}

// ───────────────────────────── Exit (server) ─────────────────────────────

type ServerConfig struct {
	ListenAddr string
	PSK        []byte
	PadMax     int
	Window     int    // per-stream flow-control window in bytes (0 = default)
	SNI        string // reality-udp: if set, require the client's ClientHello SNI to match

	// Transport selects how carriers arrive: "udp", "reality-udp" or "browser".
	Transport string

	// Domain + ACMEDir configure the "browser" transport: the exit obtains a real
	// Let's Encrypt certificate for Domain (HTTP-01 on :80) and serves real HTTP/3.
	Domain  string
	ACMEDir string // cert cache dir (default /etc/tvtunx/acme)
	// Label, when set, enables PSK-rotating subdomains under *.<Label>.<Domain>;
	// the exit issues per-name certs only for PSK-valid rotating hostnames.
	Label string
	// CFToken, when set, lets the exit auto-renew the DNS-01 wildcard certificate
	// via the Cloudflare API (no open port, no manual step).
	CFToken string

	// UDPTargetMbit paces the UDP carrier to this rate (0 = unpaced).
	UDPTargetMbit int
}

// accepter is the common accept side of every carrier listener (UDP or TCP).
type accepter interface {
	Accept() (net.Conn, error)
}

// acceptInto accepts carriers from l forever, serving each as a tunnel, and
// reports the terminal error (listener closed/failed) on errc.
func acceptInto(l accepter, cfg ServerConfig, errc chan<- error) {
	for {
		conn, err := l.Accept()
		if err != nil {
			errc <- err
			return
		}
		go serveTunnel(conn, cfg)
	}
}

// rudpNetListener adapts *rudp.Listener (whose Accept returns *rudp.Conn) to the
// accepter interface (Accept returning net.Conn).
type rudpNetListener struct{ l *rudp.Listener }

func (a rudpNetListener) Accept() (net.Conn, error) { return a.l.Accept() }

// RunServer runs the exit as a DUAL-STACK listener: for every transport it
// serves the transport's UDP carrier AND a TCP fallback carrier on the SAME
// port, concurrently. A relay can connect over whichever the network permits, so
// a firewall that blocks only UDP (or only TCP) no longer stops the tunnel.
func RunServer(cfg ServerConfig) error {
	if cfg.Transport == TransportBrowser {
		return runBrowserServer(cfg)
	}

	// UDP carrier for the selected transport.
	var udp accepter
	var udpCloser interface{ Close() error }
	switch cfg.Transport {
	case TransportRealityUDP:
		ql, err := qmask.Listen(cfg.ListenAddr, qmask.Config{
			SNI:        cfg.SNI, // if set, require the client's ClientHello SNI to match
			PSK:        cfg.PSK,
			TargetMbit: cfg.UDPTargetMbit,
		})
		if err != nil {
			return err
		}
		udp, udpCloser = ql, ql
	default: // TransportUDP
		rl, err := rudp.Listen(cfg.ListenAddr, rudp.Config{PSK: cfg.PSK, TargetMbit: cfg.UDPTargetMbit})
		if err != nil {
			return err
		}
		udp, udpCloser = rudpNetListener{rl}, rl
	}

	// TCP fallback carrier on the SAME port (self-signed cert; the relay never
	// verifies it — the PSK knock authenticates). This is what keeps the exit
	// reachable when UDP is blocked or dropped.
	tl, err := tcpcarrier.Listen(cfg.ListenAddr, tcpcarrier.Config{PSK: cfg.PSK, SNICN: cfg.SNI})
	if err != nil {
		udpCloser.Close()
		return err
	}
	log.Printf("exit listening on %s — dual-stack: UDP (%s) + TCP (TLS fallback)", cfg.ListenAddr, carrierName(cfg.Transport))

	errc := make(chan error, 2)
	go acceptInto(udp, cfg, errc)
	go acceptInto(tl, cfg, errc)
	return <-errc
}

// runBrowserServer runs the exit for the "browser" transport: it obtains a real
// Let's Encrypt certificate for cfg.Domain (ACME HTTP-01 on :80), then serves real
// HTTP/3 on cfg.ListenAddr — a real website to any visitor, and a tunnel carrier to
// authenticated (PSK) clients.
func runBrowserServer(cfg ServerConfig) error {
	if cfg.Domain == "" {
		return &simpleErr{"browser transport: -domain is required on the exit"}
	}
	cacheDir := cfg.ACMEDir
	if cacheDir == "" {
		cacheDir = "/etc/tvtunx/acme"
	}

	// Resolve the certificate source once; both the UDP (HTTP/3) and TCP (HTTPS)
	// carriers present the SAME real certificate for the domain.
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	if cert, err := acmedns.LoadCert(cacheDir); err == nil {
		// DNS-01 wildcard cert present (from `tvtunx cert`): no :80 responder
		// needed — works when :80/:443 are taken by another service (e.g. a panel
		// node's xray).
		holder := &certHolder{}
		holder.set(cert)
		getCert = holder.get
		if cfg.CFToken != "" && cfg.Label != "" {
			go autoRenewCert(cacheDir, cfg.Domain, cfg.Label, cfg.CFToken, holder)
		}
		log.Printf("browser: using DNS-01 wildcard cert for *.%s.%s (no :80 needed)", cfg.Label, cfg.Domain)
	} else {
		// HTTP-01 path: obtain/renew via an ACME responder on :80. HostPolicy
		// bounds which names we issue for (the bare domain plus PSK-valid rotating
		// names when Label is set), so scanners cannot drive arbitrary issuance.
		var policy autocert.HostPolicy
		if cfg.Label != "" {
			dom, label, psk := cfg.Domain, cfg.Label, cfg.PSK
			policy = func(_ context.Context, host string) error {
				if host == dom || browser.ValidRotatingName(host, dom, label, psk, time.Now()) {
					return nil
				}
				return &simpleErr{"browser: host not allowed: " + host}
			}
		} else {
			policy = autocert.HostWhitelist(cfg.Domain)
		}
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: policy, Cache: autocert.DirCache(cacheDir)}
		go func() {
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Printf("browser: ACME HTTP-01 responder on :80 failed: %v (cert issuance/renewal needs :80 open)", err)
			}
		}()
		getCert = m.GetCertificate
		log.Printf("browser: HTTP-01 issuance for %s — ensure :80/tcp is open and the A record points here", cfg.Domain)
	}

	// UDP carrier: real HTTP/3 (quic-go) with the real certificate.
	uaddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	bl := browser.Listen(pc, &tls.Config{GetCertificate: getCert}, cfg.PSK)

	// TCP fallback carrier: ordinary HTTPS bytes — TLS with the SAME real cert and
	// an h2 ALPN — plus the PSK knock. When UDP/HTTP-3 is blocked, the relay falls
	// back to this and the exit still looks like a normal web server on TCP.
	tcpTLS := &tls.Config{GetCertificate: getCert, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	tl, err := tcpcarrier.Listen(cfg.ListenAddr, tcpcarrier.Config{PSK: cfg.PSK, TLS: tcpTLS})
	if err != nil {
		bl.Close()
		pc.Close()
		return err
	}
	log.Printf("exit listening on %s — dual-stack: UDP (HTTP/3) + TCP (HTTPS) for %s", cfg.ListenAddr, cfg.Domain)

	errc := make(chan error, 2)
	go acceptInto(bl, cfg, errc)
	go acceptInto(tl, cfg, errc)
	return <-errc
}

// certHolder serves the current certificate and allows a safe hot-swap on renewal.
type certHolder struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func (h *certHolder) set(c *tls.Certificate) { h.mu.Lock(); h.cert = c; h.mu.Unlock() }
func (h *certHolder) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cert, nil
}

// autoRenewCert (Cloudflare mode) re-obtains the wildcard cert before expiry and
// hot-swaps it into the running server, so the browser transport never needs a
// manual renewal or any open port.
func autoRenewCert(cacheDir, domain, label, cfToken string, holder *certHolder) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for range t.C {
		if !acmedns.NeedsRenew(cacheDir) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		err := acmedns.ObtainWildcard(ctx, domain, label, cacheDir,
			&acmedns.CloudflareProvider{Token: cfToken, Zone: domain}, false, log.Printf)
		cancel()
		if err != nil {
			log.Printf("browser: certificate auto-renew failed: %v", err)
			continue
		}
		if c, err := acmedns.LoadCert(cacheDir); err == nil {
			holder.set(c)
			log.Printf("browser: certificate renewed and reloaded")
		}
	}
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return addr
}

func exitTCP(st *mux.Stream) {
	defer st.Close()
	if st.Dest() == "" {
		return
	}
	// Diagnostic echo endpoint, reachable only through the authenticated tunnel
	// (PSK-gated). Used by `tvtunx bench` to measure pure tunnel performance
	// without involving the real destination/config.
	if st.Dest() == benchEcho {
		buf := make([]byte, 64*1024)
		for {
			n, err := st.Read(buf)
			if n > 0 {
				if _, werr := st.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	rc, err := net.DialTimeout("tcp", st.Dest(), dialTimeout)
	if err != nil {
		return
	}
	defer rc.Close()
	tune(rc)
	pipeTCP(rc, st)
}

// benchEcho is the special dest that routes to the exit's echo endpoint.
const benchEcho = "@tvtunx-bench-echo"

// exitUDP dials the destination as UDP and relays datagrams both ways.
func exitUDP(st *mux.Stream) {
	defer st.Close()
	if st.Dest() == "" {
		return
	}
	raddr, err := net.ResolveUDPAddr("udp", st.Dest())
	if err != nil {
		return
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return
	}
	defer uc.Close()

	// destination -> tunnel
	go func() {
		b := make([]byte, udpReadBuf)
		for {
			_ = uc.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, rerr := uc.Read(b)
			if n > 0 {
				if werr := st.WriteDatagram(b[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// tunnel -> destination
	for {
		d, rerr := st.ReadDatagram()
		if rerr != nil {
			return
		}
		_ = uc.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
		if _, werr := uc.Write(d); werr != nil {
			return
		}
	}
}

// ───────────────────────────── helpers ─────────────────────────────

func listenAddr(port int) string {
	return net.JoinHostPort("0.0.0.0", itoa(port))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [11]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func pipeTCP(a net.Conn, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 64*1024)
		io.CopyBuffer(a, b, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		io.CopyBuffer(b, a, buf)
		done <- struct{}{}
	}()
	// When either direction ends, close both so the other goroutine unblocks
	// immediately instead of leaking (blocked in Read) until the session dies.
	<-done
	a.Close()
	b.Close()
	<-done
}
