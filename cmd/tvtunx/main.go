// tvtunx — a DPI-resistant, loss-tolerant TCP+UDP port-forwarding tunnel core.
//
// It carries whatever you forward (a VLESS/VMess/WireGuard config, plain TCP/UDP)
// between a relay inside the restricted network and an exit abroad, over a UDP
// carrier that survives the packet loss and throttling that collapse TCP tunnels.
//
// Two transports (both UDP-carried):
//
//	udp          reliable-UDP: no TCP-over-TCP meltdown, loss is retransmitted
//	             instead of collapsing the rate. Fastest; opening packets are
//	             PSK-obfuscated but not disguised as a named protocol.
//	reality-udp  QUIC masquerade over the same carrier: the opening packet is a
//	             real QUIC Initial with a Chrome ClientHello and a real SNI, so a
//	             DPI sees ordinary HTTP/3 to an allowed site. Camouflage + speed.
//
// Usage:
//
//	tvtunx keygen
//	    Print a fresh pre-shared key (use the same one on both ends).
//
//	tvtunx server -listen 0.0.0.0:443 -psk <PSK> -transport reality-udp
//	    Run on the exit server (abroad).
//
//	tvtunx client -server <exit-ip>:443 -psk <PSK> -transport reality-udp \
//	              -sni www.cloudflare.com -forward 443:127.0.0.1:8443
//	    Run on the relay. -forward may be repeated.
//
//	tvtunx diag -server <exit-ip>:443 -psk <PSK> -transport reality-udp -sni www.cloudflare.com
//	    Test tunnel health end to end; report and suggest, never auto-change.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/local/tvtunx/internal/acmedns"
	"github.com/local/tvtunx/internal/tunnel"
)

var version = "dev"

const (
	cReset = "\033[0m"
	cBold  = "\033[1m"
	cDim   = "\033[2m"
	cCyan  = "\033[36m"
	cGreen = "\033[32m"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "keygen":
		keygen()
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "diag", "diagnose":
		runDiag(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	case "cert":
		runCert(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("tvtunx %s\n", version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`%s%sTVtunX%s %s— DPI-resistant, loss-tolerant TCP+UDP tunnel core%s

%sCOMMANDS%s
  keygen                                    generate a secure pre-shared key
  server  -listen H:P -psk KEY              run the exit role (abroad)
  client  -server H:P -psk KEY -forward F   run the relay role (F repeatable)
  diag    -server H:P -psk KEY              test tunnel health end to end
  bench   -server H:P -psk KEY              measure tunnel throughput & latency
  cert    -domain D -label L -dns M         get a browser-transport TLS cert (DNS-01)
  version                                   print version

%sTRANSPORTS%s  (-transport, same value on both ends)
  udp           reliable-UDP (fastest; obfuscated, not protocol-disguised)
  reality-udp   QUIC masquerade over reliable-UDP (looks like HTTP/3; needs -sni)
  browser       REAL HTTP/3 to a real site with a real Let's Encrypt cert
                (the exit serves a website; needs -domain + a DNS A record)

%sFORWARD FORMAT%s  (client -forward)
  LISTEN_PORT:DEST_HOST:DEST_PORT
  %sexample: 443:127.0.0.1:8443  (relay :443 TCP+UDP -> 127.0.0.1:8443 at exit)%s

%sEXAMPLE%s  (reality-udp)
  %s# 1. generate a key (once), use the SAME value on both ends%s
  tvtunx keygen

  %s# 2. on the exit server (abroad)%s
  tvtunx server -listen 0.0.0.0:443 -psk 'PASTE_KEY' -transport reality-udp

  %s# 3. on the relay server%s
  tvtunx client -server 203.0.113.9:443 -psk 'PASTE_KEY' -transport reality-udp \
                -sni www.cloudflare.com -forward 443:127.0.0.1:8443

  %s# 4. verify%s
  tvtunx diag -server 203.0.113.9:443 -psk 'PASTE_KEY' -transport reality-udp -sni www.cloudflare.com
`,
		cBold, cCyan, cReset, cDim, cReset,
		cBold, cReset,
		cBold, cReset,
		cBold, cReset,
		cDim, cReset,
		cBold, cReset,
		cDim, cReset,
		cDim, cReset,
		cDim, cReset,
		cDim, cReset,
	)
}

func keygen() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(b))
}

func decodePSK(s string) []byte {
	if s == "" {
		fmt.Fprintln(os.Stderr, "error: -psk is required (run 'tvtunx keygen' first)")
		os.Exit(1)
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) >= 16 {
		return b
	}
	return []byte(s)
}

// validTransport reports whether t is one of the supported transports.
func validTransport(t string) bool {
	return t == tunnel.TransportUDP || t == tunnel.TransportRealityUDP || t == tunnel.TransportBrowser
}

func checkTransport(t string) {
	if !validTransport(t) {
		fmt.Fprintf(os.Stderr, "error: -transport must be 'udp', 'reality-udp' or 'browser' (got %q)\n", t)
		os.Exit(1)
	}
}

func checkNet(n string) {
	switch n {
	case "auto", "udp", "tcp", "":
	default:
		fmt.Fprintf(os.Stderr, "error: -net must be 'auto', 'udp' or 'tcp' (got %q)\n", n)
		os.Exit(1)
	}
}

// forwardList collects repeated -forward flags.
type forwardList []tunnel.Forward

func (f *forwardList) String() string { return "" }
func (f *forwardList) Set(v string) error {
	// LISTEN_PORT:DEST_HOST:DEST_PORT
	i := strings.Index(v, ":")
	if i < 0 {
		return fmt.Errorf("bad -forward %q (want LISTEN_PORT:DEST_HOST:DEST_PORT)", v)
	}
	lp, err := strconv.Atoi(v[:i])
	if err != nil || lp < 1 || lp > 65535 {
		return fmt.Errorf("bad listen port in %q", v)
	}
	dest := v[i+1:]
	if !strings.Contains(dest, ":") {
		return fmt.Errorf("bad dest in %q (want HOST:PORT)", v)
	}
	*f = append(*f, tunnel.Forward{ListenPort: lp, Dest: dest})
	return nil
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:443", "listen address (UDP)")
	psk := fs.String("psk", "", "pre-shared key")
	pad := fs.Int("pad", 512, "max per-frame padding bytes")
	window := fs.Int("window", 1024, "per-stream flow-control window in KB")
	transport := fs.String("transport", "reality-udp", "carrier transport: udp, reality-udp or browser")
	sni := fs.String("sni", "", "reality-udp: if set, require the client's ClientHello SNI to match (use the SAME value as the relay)")
	domain := fs.String("domain", "", "browser: the real domain this exit serves (gets a free Let's Encrypt cert)")
	label := fs.String("label", "", "browser: wildcard label for PSK-rotating subdomains (*.<label>.<domain>); empty = use domain directly")
	cfToken := fs.String("cf-token", "", "browser: Cloudflare API token to auto-renew the DNS-01 wildcard cert (optional)")
	acmeDir := fs.String("acme-dir", "/etc/tvtunx/acme", "browser: directory to cache the TLS certificate")
	udpTarget := fs.Int("udp-target", 0, "pace the UDP carrier to this Mbit/s (0 = unpaced)")
	_ = fs.Parse(args)
	checkTransport(*transport)
	if *transport == tunnel.TransportBrowser && *domain == "" {
		fmt.Fprintln(os.Stderr, "error: -domain is required for -transport browser")
		os.Exit(1)
	}

	err := tunnel.RunServer(tunnel.ServerConfig{
		ListenAddr:    *listen,
		PSK:           decodePSK(*psk),
		PadMax:        *pad,
		Window:        *window * 1024,
		SNI:           *sni,
		Domain:        *domain,
		Label:         *label,
		CFToken:       *cfToken,
		ACMEDir:       *acmeDir,
		Transport:     *transport,
		UDPTargetMbit: *udpTarget,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server := fs.String("server", "", "exit server host:port")
	psk := fs.String("psk", "", "pre-shared key")
	pad := fs.Int("pad", 512, "max per-frame padding bytes")
	sni := fs.String("sni", "", "reality-udp: real site name shown in the ClientHello")
	domain := fs.String("domain", "", "browser: the exit's real domain to connect to (must match the exit)")
	label := fs.String("label", "", "browser: wildcard label for PSK-rotating subdomains (must match the exit)")
	doh := fs.String("doh", "", "browser: resolve the exit's hostname over this DoH endpoint (e.g. https://cloudflare-dns.com/dns-query) instead of a pinned IP")
	proto := fs.String("proto", "both", "which to forward: tcp, udp, or both")
	window := fs.Int("window", 1024, "per-stream flow-control window in KB")
	transport := fs.String("transport", "reality-udp", "carrier transport: udp, reality-udp or browser")
	netMode := fs.String("net", "auto", "carrier network: auto (UDP, then TCP fallback if UDP is blocked), udp, or tcp")
	udpTarget := fs.Int("udp-target", 0, "pace the UDP carrier to this Mbit/s (0 = unpaced)")
	rotate := fs.Int("rotate", 0, "retire each tunnel connection after N seconds to beat ISP per-flow throttling (0 = off)")
	pool := fs.Int("pool", 0, "number of parallel tunnel connections (0 = default 6; raise to beat per-flow throttling)")
	var fwds forwardList
	fs.Var(&fwds, "forward", "LISTEN_PORT:DEST_HOST:DEST_PORT (repeatable)")
	_ = fs.Parse(args)
	checkTransport(*transport)
	checkNet(*netMode)

	if *server == "" {
		fmt.Fprintln(os.Stderr, "error: -server is required")
		os.Exit(1)
	}
	if *transport == tunnel.TransportRealityUDP && *sni == "" {
		fmt.Fprintln(os.Stderr, "error: -sni is required for -transport reality-udp (use a real, allowed site name)")
		os.Exit(1)
	}
	if *transport == tunnel.TransportBrowser && *domain == "" {
		fmt.Fprintln(os.Stderr, "error: -domain is required for -transport browser (the exit's real domain)")
		os.Exit(1)
	}
	if len(fwds) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one -forward is required")
		os.Exit(1)
	}
	switch *proto {
	case "tcp", "udp", "both":
	default:
		fmt.Fprintln(os.Stderr, "error: -proto must be tcp, udp, or both")
		os.Exit(1)
	}
	for i := range fwds {
		fwds[i].Proto = *proto
	}
	err := tunnel.RunClient(tunnel.ClientConfig{
		ServerAddr:    *server,
		PSK:           decodePSK(*psk),
		PadMax:        *pad,
		Forwards:      fwds,
		SNI:           *sni,
		Domain:        *domain,
		Label:         *label,
		DoH:           *doh,
		Window:        *window * 1024,
		Transport:     *transport,
		Net:           *netMode,
		UDPTargetMbit: *udpTarget,
		RotateSec:     *rotate,
		PoolSize:      *pool,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
}

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	server := fs.String("server", "", "exit server host:port")
	psk := fs.String("psk", "", "pre-shared key")
	sni := fs.String("sni", "", "reality-udp: real site name in the ClientHello")
	domain := fs.String("domain", "", "browser: the exit's real domain")
	label := fs.String("label", "", "browser: rotating-subdomain label (match the exit)")
	secs := fs.Int("secs", 5, "throughput/under-load test duration")
	window := fs.Int("window", 0, "per-stream window in KB to test (0 = installed default)")
	transport := fs.String("transport", "reality-udp", "carrier transport: udp, reality-udp or browser")
	netMode := fs.String("net", "auto", "carrier network: auto (UDP, then TCP fallback), udp, or tcp")
	udpTarget := fs.Int("udp-target", 0, "pace the UDP carrier to this Mbit/s (0 = unpaced)")
	_ = fs.Parse(args)
	checkTransport(*transport)
	checkNet(*netMode)
	if *server == "" || (*transport == tunnel.TransportRealityUDP && *sni == "") || (*transport == tunnel.TransportBrowser && *domain == "") {
		fmt.Fprintln(os.Stderr, "error: -server is required (-sni for reality-udp, -domain for browser)")
		os.Exit(1)
	}
	rep := tunnel.RunBench(tunnel.BenchConfig{
		ServerAddr:    *server,
		PSK:           decodePSK(*psk),
		SNI:           *sni,
		Domain:        *domain,
		Label:         *label,
		Seconds:       *secs,
		Window:        *window * 1024,
		Transport:     *transport,
		Net:           *netMode,
		UDPTargetMbit: *udpTarget,
	})
	fmt.Printf("\n%s%s  TUNNEL BENCHMARK%s\n", cBold, cCyan, cReset)
	fmt.Printf("%s  ──────────────────────────────────────────────%s\n", cDim, cReset)
	for _, l := range rep.Lines {
		fmt.Println("   " + l)
	}
	if len(rep.Notes) > 0 {
		fmt.Printf("\n%s%s  WHAT THIS MEANS%s\n", cBold, cCyan, cReset)
		fmt.Printf("%s  ──────────────────────────────────────────────%s\n", cDim, cReset)
		for _, n := range rep.Notes {
			fmt.Println("   → " + n)
		}
	}
	// Machine-readable line for scripts (the installer parses this).
	fmt.Printf("TVTUNX_BENCH throughput_mbit=%.1f idle_rtt_ms=%.0f underload_rtt_ms=%.0f\n",
		rep.ThroughputMbit, rep.IdleRTTms, rep.UnderLoadRTTms)
	fmt.Println()
}

// runCert obtains (or renews) the browser transport's wildcard certificate via
// ACME DNS-01 — no open port needed, so it works even when :80/:443 are taken.
func runCert(args []string) {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	domain := fs.String("domain", "", "your base domain (the Cloudflare zone), e.g. example.com")
	label := fs.String("label", "t", "wildcard label; the cert covers *.<label>.<domain>")
	acmeDir := fs.String("acme-dir", "/etc/tvtunx/acme", "where to store the certificate")
	dns := fs.String("dns", "manual", "DNS-01 method: 'cloudflare' (API token) or 'manual' (you add the TXT record)")
	cfToken := fs.String("cf-token", "", "cloudflare: API token with Zone:DNS:Edit on the zone")
	staging := fs.Bool("staging", false, "use Let's Encrypt staging (for testing; not a real cert)")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "error: -domain is required")
		os.Exit(1)
	}
	var prov acmedns.Provider
	switch *dns {
	case "cloudflare":
		if *cfToken == "" {
			fmt.Fprintln(os.Stderr, "error: -cf-token is required for -dns cloudflare")
			os.Exit(1)
		}
		prov = &acmedns.CloudflareProvider{Token: *cfToken, Zone: *domain}
	case "manual":
		prov = &acmedns.ManualProvider{}
	default:
		fmt.Fprintln(os.Stderr, "error: -dns must be 'cloudflare' or 'manual'")
		os.Exit(1)
	}
	fmt.Printf("%s%s  Getting a wildcard certificate for %s%s\n", cBold, cCyan, acmedns.WildcardName(*domain, *label), cReset)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := acmedns.ObtainWildcard(ctx, *domain, *label, *acmeDir, prov, *staging, func(f string, a ...any) {
		fmt.Printf("   "+f+"\n", a...)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "%scert failed: %v%s\n", cBold, err, cReset)
		os.Exit(1)
	}
	fmt.Printf("   %s%s✓ certificate ready in %s%s\n", cBold, cGreen, *acmeDir, cReset)
}

func runDiag(args []string) {
	fs := flag.NewFlagSet("diag", flag.ExitOnError)
	server := fs.String("server", "", "exit server host:port")
	psk := fs.String("psk", "", "pre-shared key")
	probe := fs.String("probe", "example.com:80", "test destination reached through the tunnel")
	sni := fs.String("sni", "", "reality-udp: real site name in the ClientHello")
	domain := fs.String("domain", "", "browser: the exit's real domain")
	label := fs.String("label", "", "browser: rotating-subdomain label (match the exit)")
	doh := fs.String("doh", "", "browser: resolve the exit's hostname over this DoH endpoint instead of a pinned IP")
	transport := fs.String("transport", "reality-udp", "carrier transport: udp, reality-udp or browser")
	netMode := fs.String("net", "auto", "carrier network: auto (UDP, then TCP fallback), udp, or tcp")
	udpTarget := fs.Int("udp-target", 0, "pace the UDP carrier to this Mbit/s (0 = unpaced)")
	_ = fs.Parse(args)
	checkTransport(*transport)
	checkNet(*netMode)
	if *server == "" {
		fmt.Fprintln(os.Stderr, "error: -server is required")
		os.Exit(1)
	}
	if *transport == tunnel.TransportBrowser && *domain == "" {
		fmt.Fprintln(os.Stderr, "error: -domain is required for -transport browser")
		os.Exit(1)
	}
	rep := tunnel.RunDiag(tunnel.DiagConfig{
		ServerAddr:    *server,
		PSK:           decodePSK(*psk),
		Probe:         *probe,
		SNI:           *sni,
		Domain:        *domain,
		Label:         *label,
		DoH:           *doh,
		Transport:     *transport,
		Net:           *netMode,
		UDPTargetMbit: *udpTarget,
	})

	fmt.Printf("\n%s%s  DIAGNOSTICS%s\n", cBold, cCyan, cReset)
	fmt.Printf("%s  ──────────────────────────────────────────────%s\n", cDim, cReset)
	for _, l := range rep.Lines {
		fmt.Println("   " + l)
	}
	if len(rep.Suggestions) > 0 {
		fmt.Printf("\n%s%s  SUGGESTIONS%s\n", cBold, cCyan, cReset)
		fmt.Printf("%s  ──────────────────────────────────────────────%s\n", cDim, cReset)
		for _, s := range rep.Suggestions {
			fmt.Println("   → " + s)
		}
	}
	fmt.Println()
	if rep.OK {
		fmt.Printf("   %s%s✓ overall: healthy%s\n\n", cBold, cGreen, cReset)
	} else {
		fmt.Printf("   %s✗ overall: has issues%s\n\n", cBold, cReset)
		os.Exit(2)
	}
}
