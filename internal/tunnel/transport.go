package tunnel

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/local/tvtunx/internal/browser"
	"github.com/local/tvtunx/internal/frame"
	"github.com/local/tvtunx/internal/handshake"
	"github.com/local/tvtunx/internal/mux"
	"github.com/local/tvtunx/internal/qmask"
	"github.com/local/tvtunx/internal/rudp"
	"github.com/local/tvtunx/internal/tcpcarrier"
)

// Transport names (v1.0.0 ships exactly two, both UDP-carried):
//
//   udp         reliable-UDP carrier (internal/rudp). No outer TCP, so no
//               TCP-over-TCP meltdown; packet loss is recovered by retransmission
//               instead of collapsing the rate, which beats ISP throttling. The
//               opening datagrams are PSK-obfuscated but not disguised as any
//               named protocol — fastest, lowest overhead, for links that only
//               throttle rather than classify UDP.
//
//   reality-udp QUIC-masquerade over the same reliable-UDP carrier
//               (internal/qmask). The opening packet is a real QUIC v1 Initial
//               carrying a Chrome ClientHello with a real SNI, so a DPI that
//               inspects QUIC sees an ordinary HTTP/3 handshake to an allowed
//               site; a hidden PSK token tells our client from a real browser.
//               After the handshake both ends switch to the reliable-UDP data
//               phase, framed as QUIC 1-RTT packets. Camouflage + loss-tolerance.
const (
	TransportUDP        = "udp"
	TransportRealityUDP = "reality-udp"
	TransportBrowser    = "browser"
)

// browserInsecureTLS makes the browser-transport client skip certificate
// verification. It is false in production and set true only by in-process tests
// that use a self-signed cert (real deployments verify the real Let's Encrypt cert).
var browserInsecureTLS = false

// carrierName returns a human-readable transport label for diagnostics.
func carrierName(t string) string {
	switch t {
	case TransportRealityUDP:
		return "reality-udp (QUIC-masquerade)"
	case TransportBrowser:
		return "browser (real HTTP/3 to a real site)"
	default:
		return "udp (reliable-UDP)"
	}
}

// ───────────────────────────── client carrier ─────────────────────────────

// dialCarrierUDP establishes the UDP-based carrier for the selected transport
// (browser / reality-udp / udp). The inner stack (PSK handshake -> frame -> mux)
// is identical regardless of transport. When the UDP path is blocked, the relay
// falls back to dialCarrierTCP (see dialSession).
func dialCarrierUDP(cfg ClientConfig) (net.Conn, error) {
	switch cfg.Transport {
	case TransportBrowser:
		// Connect to the exit as a real browser: a genuine HTTP/3 request to the
		// real domain (verified against its real certificate), pinned to the exit's
		// address. The tunnel rides inside that request's duplex stream.
		var tc *tls.Config
		if browserInsecureTLS {
			tc = &tls.Config{InsecureSkipVerify: true} // tests only (self-signed cert)
		}
		sni := cfg.Domain
		if cfg.Label != "" {
			// PSK-rotating subdomain: a fresh hostname per day under *.label.domain.
			sni = browser.RotatingName(cfg.Domain, cfg.Label, cfg.PSK, time.Now())
		}
		addr := cfg.ServerAddr
		if cfg.DoH != "" {
			// Resolve the exit's hostname over encrypted DNS instead of a pinned IP.
			ip, err := browser.ResolveDoH(cfg.DoH, sni, nil)
			if err != nil {
				return nil, err
			}
			port := "443"
			if _, p, e := net.SplitHostPort(cfg.ServerAddr); e == nil && p != "" {
				port = p
			}
			addr = net.JoinHostPort(ip, port)
		}
		return browser.Dial(addr, sni, cfg.PSK, tc)
	case TransportRealityUDP:
		return qmask.Dial(cfg.ServerAddr, qmask.Config{
			SNI:        cfg.SNI,
			PSK:        cfg.PSK,
			TargetMbit: cfg.UDPTargetMbit,
		})
	default: // TransportUDP
		return rudp.Dial(cfg.ServerAddr, rudp.Config{
			TargetMbit: cfg.UDPTargetMbit,
			PSK:        cfg.PSK,
		})
	}
}

// dialCarrierTCP establishes the TCP fallback carrier (TLS + PSK knock). It is
// transport-agnostic — a reliable TLS stream that looks like HTTPS on the wire —
// but it picks the ClientHello SNI to match the chosen transport's disguise so a
// relay that switches from UDP to TCP keeps presenting a consistent hostname.
func dialCarrierTCP(cfg ClientConfig) (net.Conn, error) {
	return tcpcarrier.Dial(cfg.ServerAddr, tcpcarrier.DialConfig{
		PSK: cfg.PSK,
		SNI: tcpSNI(cfg),
	})
}

// dialCarrierProbe (diagnostics) returns a live carrier and which network it
// used ("udp" or "tcp"), honoring cfg.Net. In auto mode it tries the transport's
// UDP carrier first and falls back to TCP, exactly as a relay would — so `tvtunx
// diag` reports the path the tunnel will actually take.
func dialCarrierProbe(cfg ClientConfig) (net.Conn, string, error) {
	switch strings.ToLower(cfg.Net) {
	case "udp":
		c, err := dialCarrierUDP(cfg)
		return c, "udp", err
	case "tcp":
		c, err := dialCarrierTCP(cfg)
		return c, "tcp", err
	}
	if c, err := dialCarrierUDP(cfg); err == nil {
		return c, "udp", nil
	}
	c, err := dialCarrierTCP(cfg)
	if err != nil {
		return nil, "", err
	}
	return c, "tcp", nil
}

// tcpSNI returns the TLS ServerName the TCP fallback should present for this
// transport: the browser transport's real (possibly rotating) domain, the
// reality-udp pinned site, or the configured SNI for plain udp (may be empty).
func tcpSNI(cfg ClientConfig) string {
	switch cfg.Transport {
	case TransportBrowser:
		if cfg.Label != "" {
			return browser.RotatingName(cfg.Domain, cfg.Label, cfg.PSK, time.Now())
		}
		return cfg.Domain
	case TransportRealityUDP:
		return cfg.SNI
	default:
		return cfg.SNI
	}
}

// ───────────────────────────── shared inner pipeline ─────────────────────────────

// serveTunnel runs the PSK handshake, frame layer and mux over an established
// carrier, then relays each accepted stream. Used by both transports.
func serveTunnel(carrier net.Conn, cfg ServerConfig) {
	keys, err := handshake.Server(carrier, cfg.PSK)
	if err != nil {
		carrier.Close()
		return
	}
	fc, err := frame.NewConn(carrier, keys.SendKey, keys.RecvKey, keys.SendLenKey, keys.RecvLenKey)
	if err != nil {
		carrier.Close()
		return
	}
	pm := cfg.PadMax
	if pm == 0 {
		pm = defaultPadMax
	}
	sess := mux.New(fc, false, pm, cfg.Window)
	defer sess.Close()
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		if st.Kind == mux.KindUDP {
			go exitUDP(st)
		} else {
			go exitTCP(st)
		}
	}
}
