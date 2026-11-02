package tunnel

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/local/tvtunx/internal/mux"
)

// BenchConfig drives a tunnel benchmark run from the relay toward the exit.
type BenchConfig struct {
	ServerAddr string
	PSK        []byte
	SNI        string
	Seconds    int // throughput / under-load test duration (default 5)
	Window     int // per-stream window in bytes (0 = default); for tuning

	// Transport selection (mirrors ClientConfig): "udp", "reality-udp" or "browser".
	Transport     string
	Domain        string // browser transport
	Label         string // browser transport (rotating subdomains)
	UDPTargetMbit int
}

// BenchReport holds measured results. All times are milliseconds.
type BenchReport struct {
	Lines []string
	Notes []string
	OK    bool

	// machine-readable results for scripts (the installer reads these)
	ThroughputMbit float64
	IdleRTTms      float64
	UnderLoadRTTms float64
}

func (r *BenchReport) add(f string, a ...any)  { r.Lines = append(r.Lines, fmt.Sprintf(f, a...)) }
func (r *BenchReport) note(f string, a ...any) { r.Notes = append(r.Notes, fmt.Sprintf(f, a...)) }

// RunBench measures the tunnel's own performance using the exit's echo
// endpoint, isolating the tunnel from the real config/node.
func RunBench(cfg BenchConfig) *BenchReport {
	r := &BenchReport{OK: true}
	secs := cfg.Seconds
	if secs <= 0 {
		secs = 5
	}
	ccfg := ClientConfig{
		ServerAddr: cfg.ServerAddr, PSK: cfg.PSK, SNI: cfg.SNI, Domain: cfg.Domain, Label: cfg.Label, Window: cfg.Window,
		Transport: cfg.Transport, UDPTargetMbit: cfg.UDPTargetMbit,
	}

	// 1) Tunnel session handshake time (carrier + PSK).
	t0 := time.Now()
	sess, err := dialSession(ccfg)
	if err != nil {
		r.OK = false
		r.add("tunnel handshake: FAILED (%v)", err)
		r.note("Can't reach the exit through the tunnel. Most likely the PSK differs between the two ends, or they use different transports (udp vs reality-udp). Check that PSK, transport, window and port all match, and that the exit is up.")
		return r
	}
	defer sess.Close()
	hsMS := time.Since(t0).Milliseconds()
	r.add("tunnel handshake (knock+TLS+PSK): %d ms", hsMS)

	// 2) New-stream open + first-byte latency (what a new config conn costs).
	var openSamples []float64
	for i := 0; i < 10; i++ {
		ts := time.Now()
		st, err := sess.Open(benchEcho, 0)
		if err != nil {
			r.OK = false
			r.add("open stream: FAILED (%v)", err)
			r.note("The exit may be running an old build without the bench echo. Reinstall both ends with this version.")
			return r
		}
		// write one byte, wait for echo = full round trip for a fresh stream
		if _, err := st.Write([]byte{0x7e}); err != nil {
			st.Close()
			continue
		}
		b := make([]byte, 1)
		st.SetReadDeadline(time.Now().Add(8 * time.Second))
		_, rerr := st.Read(b)
		st.Close()
		if rerr == mux.ErrReadTimeout {
			// Handshake succeeded but the tunnel carries no data back. This is the
			// "everything looks configured but nothing flows" case.
			r.OK = false
			r.add("new-stream echo: TIMED OUT (handshake OK, but no data came back)")
			r.note("The tunnel authenticated, but streams don't carry data back. Usual causes: the two ends run DIFFERENT builds (reinstall BOTH with the exact same version), or a middlebox/ISP is dropping the larger data packets while letting the handshake through (try a different tunnel port, or the reality-udp transport).")
			return r
		}
		openSamples = append(openSamples, float64(time.Since(ts).Microseconds())/1000.0)
	}
	r.add("new-stream establish (RTT, 10x): %s", summarize(openSamples))

	// 3) Idle round-trip latency on a persistent stream (ping through tunnel).
	ping, err := sess.Open(benchEcho, 0)
	if err != nil {
		r.OK = false
		r.add("ping stream: FAILED (%v)", err)
		return r
	}
	defer ping.Close()
	idle := rttSamples(ping, 20)
	r.add("idle tunnel RTT (20x): %s", summarize(idle))

	// 4) Throughput: pump on a dedicated stream for `secs`, measure one way.
	thr, err := sess.Open(benchEcho, 0)
	if err == nil {
		mbps := throughput(thr, secs)
		thr.Close()
		r.ThroughputMbit = mbps
		r.add("throughput (%ds): %.1f Mbit/s", secs, mbps)
	}
	r.IdleRTTms = med(idle)

	// 5) RTT UNDER LOAD — the key test. Run a bulk pump on one stream while
	// pinging on another. If RTT explodes vs idle, interactive traffic is being
	// starved by bulk traffic (head-of-line on the shared write path / bufferbloat).
	load, lerr := sess.Open(benchEcho, 0)
	pingL, perr := sess.Open(benchEcho, 0)
	if lerr == nil && perr == nil {
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		load.SetReadDeadline(time.Now().Add(5 * time.Second)) // can't block past this phase
		go func() {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			sink := make([]byte, 32*1024)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := load.Write(buf); err != nil {
					return
				}
				if _, err := load.Read(sink); err != nil {
					return
				}
			}
		}()
		time.Sleep(300 * time.Millisecond) // let the bulk flow ramp
		underLoad := rttSamples(pingL, 20)
		close(stop)
		wg.Wait()
		load.Close()
		pingL.Close()
		r.UnderLoadRTTms = med(underLoad)
		r.add("tunnel RTT UNDER LOAD (20x): %s", summarize(underLoad))

		// Interpret: flag only a real, large jump (ignore tiny loopback noise).
		jump := med(underLoad) - med(idle)
		if jump > 40 && med(underLoad) > med(idle)*3 {
			r.note("RTT jumps a lot under load (%.0f ms idle -> %.0f ms busy, +%.0f ms). Interactive/handshake traffic is being starved by bulk transfers — THIS is why new connections feel slow and sluggish while something is downloading. Fix: smaller frames + per-stream write fairness + smaller window to cut bufferbloat.", med(idle), med(underLoad), jump)
		} else {
			r.note("RTT stays stable under load (%.0f -> %.0f ms) — the tunnel itself is not starving interactive latency.", med(idle), med(underLoad))
		}
	}

	// General guidance on the absolute numbers.
	if med(idle) > 250 {
		r.note("Base tunnel RTT is high (%.0f ms). That's mostly the Iran<->exit network path; a closer/less-throttled exit helps more than tunnel tuning.", med(idle))
	}
	return r
}

// benchStream is what the probe helpers need: a byte stream with a read
// deadline so a stalled tunnel can't hang the benchmark.
type benchStream interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}

// rttSamples writes 1 byte and waits for the echo, N times, in ms.
func rttSamples(st benchStream, n int) []float64 {
	out := make([]float64, 0, n)
	b := make([]byte, 1)
	for i := 0; i < n; i++ {
		t := time.Now()
		if _, err := st.Write([]byte{0x7e}); err != nil {
			break
		}
		st.SetReadDeadline(time.Now().Add(6 * time.Second))
		if _, err := st.Read(b); err != nil {
			break
		}
		out = append(out, float64(time.Since(t).Microseconds())/1000.0)
		time.Sleep(50 * time.Millisecond)
	}
	return out
}

// throughput pumps data through an echo stream and returns one-way Mbit/s.
func throughput(st benchStream, secs int) float64 {
	var bytesEchoed atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	// Hard cap so the reader can never block past the test window.
	st.SetReadDeadline(time.Now().Add(time.Duration(secs)*time.Second + 3*time.Second))
	go func() {
		sink := make([]byte, 64*1024)
		for {
			n, err := st.Read(sink)
			bytesEchoed.Add(int64(n))
			if err != nil {
				close(done)
				return
			}
			select {
			case <-stop:
				close(done)
				return
			default:
			}
		}
	}()
	buf := make([]byte, 32*1024)
	start := time.Now()
	deadline := start.Add(time.Duration(secs) * time.Second)
	for time.Now().Before(deadline) {
		if _, err := st.Write(buf); err != nil {
			break
		}
	}
	close(stop)
	<-done
	elapsed := time.Since(start).Seconds()
	// bytesEchoed is the return path (one way).
	return float64(bytesEchoed.Load()) * 8 / 1e6 / elapsed
}

func summarize(s []float64) string {
	if len(s) == 0 {
		return "no samples"
	}
	cp := append([]float64(nil), s...)
	sort.Float64s(cp)
	var sum float64
	for _, v := range cp {
		sum += v
	}
	return fmt.Sprintf("min %.0f / med %.0f / avg %.0f / max %.0f ms",
		cp[0], cp[len(cp)/2], sum/float64(len(cp)), cp[len(cp)-1])
}

func med(s []float64) float64 {
	if len(s) == 0 {
		return 0
	}
	cp := append([]float64(nil), s...)
	sort.Float64s(cp)
	return cp[len(cp)/2]
}
