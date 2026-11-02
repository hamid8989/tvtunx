// Package rudp is a reliable, ordered byte-stream transport over UDP, built to
// beat the kind of ISP throttling that kills TCP: instead of collapsing on
// packet loss the way TCP's congestion control does, it keeps sending at a
// configured pace and simply retransmits what was lost. Running the tunnel over
// this (UDP) carrier instead of TCP also removes TCP-over-TCP "meltdown": when
// the user's own TCP (inside the tunnel) rides on an outer TCP, the two
// retransmit layers fight under loss and throughput craters. A UDP carrier has
// no outer TCP, so only the inner TCP handles reliability — the single-layer
// behaviour that stays fast on a lossy, throttled link.
//
// Conn implements net.Conn, so the existing handshake -> frame -> mux stack runs
// over it unchanged, exactly as it does over the TLS/reality carrier.
//
// Design (a compact selective-repeat ARQ, KCP-inspired):
//   - Each datagram is one segment: header(conv,cmd,wnd,sn,una,len) + payload.
//   - Sender keeps unacked segments, (re)sends within a window, paces output to
//     a target rate, and retransmits on RTO or on SACK gaps (fast retransmit).
//     Loss does NOT shrink the rate (this is the anti-throttle behaviour).
//   - Receiver buffers out-of-order segments, delivers them in order, and acks
//     with a cumulative `una` plus a short SACK list of segments above it.
//
// This is transport-level reliability only; confidentiality/auth remain the job
// of the frame + handshake layers that run on top.
package rudp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cmdData = 1 // carries payload
	cmdAck  = 2 // carries una + SACK list, no payload

	headerSize = 19   // conv4 cmd1 wnd2 sn4 una4 len4
	MaxPayload = 1152 // keep conv+header+payload under a safe UDP MTU
	maxSACK    = 16   // SACK seqs per ack packet
	rtoMin     = 100 * time.Millisecond
	rtoMax     = 3 * time.Second
	flushEvery = 10 * time.Millisecond
)

// keepaliveInterval bounds how long a Conn may go without SENDING anything. On a
// real path an idle UDP flow gets its NAT/firewall mapping dropped (commonly
// after ~30s on CGNAT), after which packets are blackholed and the carrier dies —
// the "connects, works, then times out and reconnects by itself" symptom. Each
// end emits a tiny keepalive ACK this often so both directions' mappings stay
// fresh and a genuinely live but app-idle tunnel is never torn down. 15s is well
// under typical mapping timeouts. It is a var so tests can shorten it.
var keepaliveInterval = 15 * time.Second

// rateCalcInterval is how often Brutal recomputes loss compensation. A var so
// tests can shorten it.
var rateCalcInterval = time.Second

// Config tunes the transport. Zero values pick sane defaults.
type Config struct {
	Conv        uint32        // conversation id; must match on both ends (0 = derive)
	WindowSegs  int           // send/recv window in segments (default 1024)
	TargetMbit  int           // pacing target in Mbit/s (0 = unpaced/as-fast-as-window)
	IdleTimeout time.Duration // close after no packets for this long (default 90s)
	PSK         []byte        // obfuscation/auth key; empty = no obfuscation (tests)
}

func (c *Config) withDefaults() {
	if c.WindowSegs <= 0 {
		c.WindowSegs = 1024
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 90 * time.Second
	}
}

// ─────────────────────────── segment ───────────────────────────

type segment struct {
	sn   uint32
	data []byte

	// sender bookkeeping
	sentNS   int64
	resendTS int64 // next time to (re)send at
	xmit     uint32
	acked    bool
}

func encode(conv uint32, cmd byte, wnd uint16, sn, una uint32, payload []byte) []byte {
	b := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint32(b[0:4], conv)
	b[4] = cmd
	binary.BigEndian.PutUint16(b[5:7], wnd)
	binary.BigEndian.PutUint32(b[7:11], sn)
	binary.BigEndian.PutUint32(b[11:15], una)
	binary.BigEndian.PutUint32(b[15:19], uint32(len(payload)))
	copy(b[headerSize:], payload)
	return b
}

// wrap-aware comparison: returns true if a is before b in sequence space.
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

// ─────────────────────────── Conn ───────────────────────────

// Conn is one reliable stream over UDP. It satisfies net.Conn.
type Conn struct {
	cfg  Config
	conv uint32

	// transport plumbing: send one datagram to the peer; inbox receives peer datagrams.
	send  func([]byte) error
	inbox chan []byte

	mu   sync.Mutex
	cond *sync.Cond

	// send side
	sndUna uint32 // oldest unacked
	sndNxt uint32 // next seq to assign
	sndBuf map[uint32]*segment
	sndW   int // peer's advertised recv window (segments)

	// recv side
	rcvNxt uint32            // next seq expected to deliver
	rcvBuf map[uint32][]byte // out-of-order segments
	readB  []byte            // in-order bytes ready for Read

	// rtt/rto
	srtt   float64
	rttvar float64
	rto    time.Duration

	// pacing / Brutal-style congestion control (Hysteria-inspired): when
	// bytesPerSec > 0 the sender holds a fixed target rate and does NOT back off
	// on loss; it instead sends FASTER by 1/deliveryFraction so goodput stays at
	// the target through a lossy/throttled link, and sizes its in-flight window to
	// the bandwidth-delay product so the pipe stays full.
	bytesPerSec int
	lastSendNS  int64
	rateComp    float64 // loss compensation multiplier (>=1)
	sentWin     int64   // bytes sent since last rate recalc
	ackWin      int64   // bytes acked since last rate recalc
	lastRateNS  int64

	closed   bool
	closeErr error
	deadline time.Time // read deadline (0 = none)
	lastRxNS int64
	lastTxNS int64 // last send time (atomic); drives keepalive

	closeOnce sync.Once
	done      chan struct{}
}

func newConn(cfg Config, conv uint32, send func([]byte) error) *Conn {
	cfg.withDefaults()
	if cfg.TargetMbit > 0 {
		// Brutal: size the in-flight window to the bandwidth-delay product (assume
		// up to ~400ms RTT) so the pipe stays full at the target rate. Both ends run
		// the same config, so the receiver advertises a matching large window.
		ws := cfg.TargetMbit * 43 // ≈ (Mbit*1e6/8 * 0.4s) / MaxPayload
		if ws > 16384 {
			ws = 16384
		}
		if ws > cfg.WindowSegs {
			cfg.WindowSegs = ws
		}
	}
	c := &Conn{
		cfg:      cfg,
		conv:     conv,
		send:     send,
		inbox:    make(chan []byte, 256),
		sndBuf:   make(map[uint32]*segment),
		rcvBuf:   make(map[uint32][]byte),
		sndW:     cfg.WindowSegs,
		rto:      rtoMin,
		lastRxNS: time.Now().UnixNano(),
		lastTxNS: time.Now().UnixNano(),
		done:     make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	c.rateComp = 1
	c.lastRateNS = time.Now().UnixNano()
	if cfg.TargetMbit > 0 {
		c.bytesPerSec = cfg.TargetMbit * 1000000 / 8
	}
	go c.rxLoop()
	go c.updateLoop()
	return c
}

// ─────────────────────────── net.Conn ───────────────────────────

func (c *Conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		c.mu.Lock()
		// backpressure: wait while the send window is full.
		for !c.closed && int(c.sndNxt-c.sndUna) >= c.cfg.WindowSegs {
			c.cond.Wait()
		}
		if c.closed {
			c.mu.Unlock()
			return total, c.errLocked()
		}
		n := len(p)
		if n > MaxPayload {
			n = MaxPayload
		}
		seg := &segment{sn: c.sndNxt, data: append([]byte(nil), p[:n]...)}
		c.sndBuf[seg.sn] = seg
		c.sndNxt++
		c.mu.Unlock()

		c.cond.Signal() // wake the update loop to send
		p = p[n:]
		total += n
	}
	// kick a flush so small writes go out promptly
	c.flush()
	return total, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.readB) == 0 && !c.closed {
		if !c.deadline.IsZero() {
			if !time.Now().Before(c.deadline) {
				return 0, timeoutErr{}
			}
			t := time.AfterFunc(time.Until(c.deadline), func() {
				c.mu.Lock()
				c.cond.Broadcast()
				c.mu.Unlock()
			})
			c.cond.Wait()
			t.Stop()
		} else {
			c.cond.Wait()
		}
	}
	if len(c.readB) == 0 {
		return 0, c.errLocked()
	}
	n := copy(p, c.readB)
	c.readB = c.readB[n:]
	return n, nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.closeErr == nil {
			c.closeErr = io.EOF
		}
		c.mu.Unlock()
		c.cond.Broadcast()
		close(c.done)
	})
	return nil
}

func (c *Conn) errLocked() error {
	if c.closeErr != nil {
		return c.closeErr
	}
	return io.EOF
}

func (c *Conn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *Conn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil } // window-bounded; no-op for now
func (c *Conn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	c.cond.Broadcast()
	return nil
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "rudp" }
func (dummyAddr) String() string  { return "rudp" }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "rudp: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// ─────────────────────────── receive path ───────────────────────────

// rxLoop decodes incoming datagrams and updates state.
func (c *Conn) rxLoop() {
	for {
		select {
		case <-c.done:
			return
		case pkt := <-c.inbox:
			c.onPacket(pkt)
		}
	}
}

func (c *Conn) onPacket(b []byte) {
	if len(b) < headerSize {
		return
	}
	conv := binary.BigEndian.Uint32(b[0:4])
	if conv != c.conv {
		return
	}
	cmd := b[4]
	wnd := binary.BigEndian.Uint16(b[5:7])
	sn := binary.BigEndian.Uint32(b[7:11])
	una := binary.BigEndian.Uint32(b[11:15])
	ln := binary.BigEndian.Uint32(b[15:19])
	if int(ln) > len(b)-headerSize {
		return
	}
	payload := b[headerSize : headerSize+int(ln)]

	c.mu.Lock()
	c.lastRxNS = time.Now().UnixNano()
	c.sndW = int(wnd)
	// advance sndUna by peer's cumulative ack
	for seqLess(c.sndUna, una) {
		if seg, ok := c.sndBuf[c.sndUna]; ok {
			c.ackSegLocked(seg)
			delete(c.sndBuf, c.sndUna)
		}
		c.sndUna++
	}

	switch cmd {
	case cmdAck:
		// SACK: payload is a list of individually-received seqs above una.
		for i := 0; i+4 <= len(payload); i += 4 {
			s := binary.BigEndian.Uint32(payload[i : i+4])
			if seg, ok := c.sndBuf[s]; ok && !seg.acked {
				c.ackSegLocked(seg)
				seg.acked = true
			}
		}
		c.cond.Broadcast() // window may have opened
	case cmdData:
		c.recvDataLocked(sn, payload)
	}
	c.mu.Unlock()

	if cmd == cmdData {
		c.sendAck() // ack outside the lock
	}
}

func (c *Conn) ackSegLocked(seg *segment) {
	if seg.acked {
		return
	}
	seg.acked = true
	c.ackWin += int64(len(seg.data)) // delivered bytes, for Brutal rate compensation
	if seg.xmit == 1 {               // only measure RTT on non-retransmitted segments (Karn)
		rtt := time.Duration(time.Now().UnixNano() - seg.sentNS)
		c.updateRTO(rtt)
	}
}

func (c *Conn) recvDataLocked(sn uint32, payload []byte) {
	// drop duplicates / already-delivered
	if seqLess(sn, c.rcvNxt) {
		return
	}
	// bound the receive window
	if int(sn-c.rcvNxt) >= c.cfg.WindowSegs {
		return
	}
	if _, ok := c.rcvBuf[sn]; !ok {
		c.rcvBuf[sn] = append([]byte(nil), payload...)
	}
	// deliver contiguous
	for {
		d, ok := c.rcvBuf[c.rcvNxt]
		if !ok {
			break
		}
		c.readB = append(c.readB, d...)
		delete(c.rcvBuf, c.rcvNxt)
		c.rcvNxt++
	}
	c.cond.Broadcast()
}

// sendAck emits a cumulative + SACK acknowledgement.
func (c *Conn) sendAck() {
	c.mu.Lock()
	una := c.rcvNxt
	wnd := uint16(c.cfg.WindowSegs - len(c.rcvBuf))
	// collect up to maxSACK out-of-order seqs above una
	sack := make([]byte, 0, maxSACK*4)
	n := 0
	for s := range c.rcvBuf {
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], s)
		sack = append(sack, tmp[:]...)
		if n++; n >= maxSACK {
			break
		}
	}
	c.mu.Unlock()
	c.emit(encode(c.conv, cmdAck, wnd, 0, una, sack))
}

// ─────────────────────────── send path / update loop ───────────────────────────

// updateLoop periodically flushes: sends new and due-for-retransmit segments.
func (c *Conn) updateLoop() {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.flush()
			c.brutalRecalc()
			c.keepalive()
			c.checkIdle()
		}
	}
}

// emit sends one datagram and records the send time, so keepalive knows when the
// flow last transmitted (and the peer's NAT mapping was last refreshed).
func (c *Conn) emit(pkt []byte) {
	atomic.StoreInt64(&c.lastTxNS, time.Now().UnixNano())
	_ = c.send(pkt)
}

// keepalive emits a bare ACK if nothing has been sent for keepaliveInterval, to
// keep the UDP path's NAT/firewall mapping alive and the peer's idle timer reset.
func (c *Conn) keepalive() {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	if time.Duration(time.Now().UnixNano()-atomic.LoadInt64(&c.lastTxNS)) >= keepaliveInterval {
		c.sendAck()
	}
}

func (c *Conn) flush() {
	now := time.Now().UnixNano()
	c.mu.Lock()
	wnd := uint16(c.cfg.WindowSegs - len(c.rcvBuf))
	// window = min(our configured window, peer's advertised window)
	limit := c.cfg.WindowSegs
	if c.sndW > 0 && c.sndW < limit {
		limit = c.sndW
	}
	var out [][]byte
	for sn := c.sndUna; seqLess(sn, c.sndNxt); sn++ {
		if int(sn-c.sndUna) >= limit {
			break
		}
		seg, ok := c.sndBuf[sn]
		if !ok || seg.acked {
			continue
		}
		needSend := false
		if seg.xmit == 0 {
			needSend = true
		} else if now >= seg.resendTS {
			needSend = true // RTO retransmit
		}
		if needSend {
			seg.xmit++
			seg.sentNS = now
			seg.resendTS = now + int64(c.rto)
			c.sentWin += int64(len(seg.data)) // for Brutal rate compensation
			out = append(out, encode(c.conv, cmdData, wnd, seg.sn, c.rcvNxt, seg.data))
		}
	}
	c.mu.Unlock()

	// send (optionally paced) outside the lock
	for _, pkt := range out {
		c.pace(len(pkt))
		c.emit(pkt)
	}
}

// pace sleeps to hold the configured target rate (no-op when unpaced). Under
// Brutal congestion control it paces at the target rate multiplied by the loss
// compensation (so goodput after loss still hits the target) — it sends FASTER on
// loss instead of backing off.
func (c *Conn) pace(n int) {
	if c.bytesPerSec <= 0 {
		return
	}
	c.mu.Lock()
	comp := c.rateComp
	c.mu.Unlock()
	if comp < 1 {
		comp = 1
	}
	eff := float64(c.bytesPerSec) * comp
	now := time.Now().UnixNano()
	gap := int64(float64(n) * float64(time.Second) / eff)
	earliest := c.lastSendNS + gap
	if now < earliest {
		time.Sleep(time.Duration(earliest - now))
		now = time.Now().UnixNano()
	}
	c.lastSendNS = now
}

// brutalRecalc updates the loss-compensation multiplier from the delivery ratio
// over the last interval: comp = 1/deliveredFraction, clamped to [1, 4]. Sending
// at target*comp keeps goodput at the target through a lossy link.
func (c *Conn) brutalRecalc() {
	if c.bytesPerSec <= 0 {
		return
	}
	now := time.Now().UnixNano()
	c.mu.Lock()
	if now-c.lastRateNS < int64(rateCalcInterval) {
		c.mu.Unlock()
		return
	}
	sent, ack := c.sentWin, c.ackWin
	c.sentWin, c.ackWin, c.lastRateNS = 0, 0, now
	if sent > 0 {
		frac := float64(ack) / float64(sent)
		if frac < 0.25 {
			frac = 0.25
		}
		if frac > 1 {
			frac = 1
		}
		c.rateComp = 1 / frac // up to 4x
	}
	c.mu.Unlock()
}

func (c *Conn) updateRTO(rtt time.Duration) {
	r := float64(rtt)
	if c.srtt == 0 {
		c.srtt = r
		c.rttvar = r / 2
	} else {
		c.rttvar = 0.75*c.rttvar + 0.25*absf(c.srtt-r)
		c.srtt = 0.875*c.srtt + 0.125*r
	}
	rto := time.Duration(c.srtt + 4*c.rttvar)
	if rto < rtoMin {
		rto = rtoMin
	}
	if rto > rtoMax {
		rto = rtoMax
	}
	c.rto = rto
}

func absf(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func (c *Conn) checkIdle() {
	c.mu.Lock()
	idle := time.Duration(time.Now().UnixNano() - c.lastRxNS)
	c.mu.Unlock()
	if idle > c.cfg.IdleTimeout {
		c.mu.Lock()
		if c.closeErr == nil {
			c.closeErr = errors.New("rudp: idle timeout")
		}
		c.mu.Unlock()
		c.Close()
	}
}
