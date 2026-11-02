package tunnel

import (
	"fmt"
	"strings"
	"time"

	"github.com/local/tvtunx/internal/frame"
	"github.com/local/tvtunx/internal/handshake"
	"github.com/local/tvtunx/internal/mux"
)

// DiagConfig drives the diagnostics run.
type DiagConfig struct {
	ServerAddr string
	PSK        []byte
	Probe      string // destination to fetch through the tunnel, e.g. example.com:80
	SNI        string // reality-udp: real site name in the ClientHello

	// Transport selection (mirrors ClientConfig): "udp", "reality-udp" or "browser".
	Transport     string
	Domain        string // browser transport
	Label         string // browser transport (rotating subdomains)
	UDPTargetMbit int
}

// Report is a human-readable diagnostic outcome. It reports and SUGGESTS; it
// never mutates config or loops autonomously (see SECURITY.md).
type Report struct {
	Lines       []string
	Suggestions []string
	OK          bool
}

func (r *Report) addf(f string, a ...any) { r.Lines = append(r.Lines, fmt.Sprintf(f, a...)) }
func (r *Report) sugg(s string)           { r.Suggestions = append(r.Suggestions, s) }

// RunDiag performs a sequence of checks and returns a report.
func RunDiag(cfg DiagConfig) *Report {
	r := &Report{OK: true}

	// 1) Carrier reachability + masquerade/handshake latency.
	ccfg := ClientConfig{
		ServerAddr: cfg.ServerAddr, PSK: cfg.PSK, SNI: cfg.SNI, Domain: cfg.Domain, Label: cfg.Label,
		Transport: cfg.Transport, UDPTargetMbit: cfg.UDPTargetMbit,
	}
	label := fmt.Sprintf("carrier to %s (transport %s)", cfg.ServerAddr, carrierName(cfg.Transport))
	t0 := time.Now()
	raw, err := dialCarrier(ccfg)
	if err != nil {
		r.OK = false
		r.addf("%s: FAILED (%v)", label, err)
		r.sugg("Open the UDP port on the exit and check the ISP is not blocking UDP on it. Confirm the PSK and transport match on both ends. Try another port (e.g. 443 / 8443 / 2083).")
		return r
	}
	connMS := time.Since(t0).Milliseconds()
	r.addf("%s: ok (%d ms)", label, connMS)

	// 2) PSK handshake latency (detects wrong PSK / fallback / DPI reset).
	// Deadline-bounded: on a PSK/transport mismatch the exit passes us through to
	// the real SNI site, which never answers our handshake — without this the
	// read would hang forever instead of reporting the misconfiguration.
	t1 := time.Now()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	keys, err := handshake.Client(raw, cfg.PSK)
	if err != nil {
		raw.Close()
		r.OK = false
		r.addf("handshake: FAILED (%v)", err)
		if strings.Contains(err.Error(), "no/short") || strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
			r.sugg("No valid reply from the exit. Most likely the PSK differs between relay and exit, or the two ends use different transports (udp vs reality-udp). Make the PSK, transport and port identical on both ends.")
		} else {
			r.sugg("Make the PSK identical on both ends: run 'tvtunx keygen' once and use that same value on the server and the client.")
		}
		return r
	}
	_ = raw.SetDeadline(time.Time{})
	hsMS := time.Since(t1).Milliseconds()
	r.addf("handshake: ok (%d ms)", hsMS)
	if hsMS > 1500 {
		r.sugg("Handshake latency is high; the path may be congested or throttled. Try another port or another exit server.")
	}

	fc, err := frame.NewConn(raw, keys.SendKey, keys.RecvKey, keys.SendLenKey, keys.RecvLenKey)
	if err != nil {
		raw.Close()
		r.OK = false
		r.addf("record layer: error (%v)", err)
		return r
	}
	sess := mux.New(fc, true, 256, 0)
	defer sess.Close()

	// 3) End-to-end payload through the tunnel.
	probe := cfg.Probe
	if probe == "" {
		probe = "example.com:80"
	}
	host := probe
	if i := strings.LastIndex(probe, ":"); i > 0 {
		host = probe[:i]
	}
	t2 := time.Now()
	st, err := sess.Open(probe, mux.KindTCP)
	if err != nil {
		r.OK = false
		r.addf("open stream to %s: FAILED (%v)", probe, err)
		return r
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: curl/8\r\n\r\n", host)
	if _, err := st.Write([]byte(req)); err != nil {
		r.OK = false
		r.addf("write through tunnel: FAILED (%v)", err)
		st.Close()
		return r
	}
	buf := make([]byte, 2048)
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := st.Read(buf)
	st.Close()
	if err == mux.ErrReadTimeout {
		r.OK = false
		r.addf("end-to-end payload: TIMED OUT (handshake OK, but nothing came back)")
		r.sugg("The tunnel authenticated but carries no data back. Usual causes: the two ends run DIFFERENT builds (reinstall BOTH with the exact same version), the exit has no working internet to reach the probe, or a middlebox is dropping the data packets while letting the handshake through (try another tunnel port, or the reality-udp transport).")
		return r
	}
	if err != nil && n == 0 {
		r.OK = false
		r.addf("no payload from %s (%v)", probe, err)
		r.sugg("The tunnel came up but the destination returned nothing. Check that the exit server itself has working internet access.")
		return r
	}
	rtMS := time.Since(t2).Milliseconds()
	head := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	r.addf("end-to-end payload: ok (%d ms) -> %q", rtMS, head)

	// 4) MTU note (informational; we don't mutate anything).
	r.addf("MTU note: if sites hang half-loaded, check MSS clamping or lower the MTU manually.")

	if r.OK {
		r.addf("result: tunnel healthy")
	}
	return r
}
