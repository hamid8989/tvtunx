// Package mux multiplexes many logical streams over one encrypted frame.Conn
// with credit-based per-stream flow control (like HTTP/2 / yamux).
//
// Wire frames (first byte of each frame body):
//
//	cmdSYN    streamID kind dst  → open a flow (kind=TCP|UDP, dst="host:port")
//	cmdDATA   streamID data      → flow payload (UDP: one frame = one datagram)
//	cmdFIN    streamID           → close
//	cmdWINDOW streamID credit(4) → grant the peer `credit` more bytes on this stream
//
// Flow control: each stream starts with a send credit equal to the peer's
// receive window. A sender may only send up to its remaining credit; when it
// runs out, only THAT stream's Write blocks — other streams keep flowing, and
// the session's readLoop never blocks. As the receiver consumes bytes it sends
// WINDOW_UPDATE frames to replenish the sender's credit. This bounds memory
// (the receiver never buffers more than one window per stream) without the
// head-of-line blocking that a shared receive buffer would cause. It is what
// lets many streams share a SMALL number of tunnel connections safely — which
// matters because opening dozens of connections to one foreign IP gets the IP
// throttled by the censor.
package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/local/tvtunx/internal/frame"
	"github.com/local/tvtunx/internal/obfs"
)

// ErrReadTimeout is returned by Read when a deadline set via SetReadDeadline
// elapses before any data arrives. Used by the diagnostics so a stalled tunnel
// is reported instead of hanging forever.
var ErrReadTimeout = errors.New("mux: read deadline exceeded")

const (
	cmdSYN    = 1
	cmdDATA   = 2
	cmdFIN    = 3
	cmdWINDOW = 4
)

// Flow kinds carried in the SYN frame.
const (
	KindTCP byte = 0
	KindUDP byte = 1
)

// defaultWindow is the per-stream receive window when none is configured.
// A single stream's max throughput is window/RTT, so on a fast, high-latency
// path (e.g. Iran<->EU, ~80ms, hundreds of Mbit/s capacity) a small window
// throttles each connection badly. 1 MB allows ~100 Mbit/s per stream at 80ms
// while keeping per-stream memory modest. It is tunable via -window.
const defaultWindow = 1024 * 1024

// Session is one multiplexed connection.
type Session struct {
	fc     *frame.Conn
	padder *obfs.Padder
	window int // per-stream receive/credit window in bytes

	wMu sync.Mutex

	mu       sync.Mutex
	streams  map[uint32]*Stream
	nextID   uint32
	isClient bool
	accept   chan *Stream
	closed   chan struct{}
	closeErr error
	once     sync.Once
}

// New builds a session. windowBytes is the per-stream flow-control window; <=0
// uses defaultWindow. Both ends should use the same value.
func New(fc *frame.Conn, isClient bool, padMax, windowBytes int) *Session {
	if windowBytes <= 0 {
		windowBytes = defaultWindow
	}
	if windowBytes < 128*1024 {
		windowBytes = 128 * 1024 // floor: keeps the credit scheme deadlock-free
	}
	s := &Session{
		fc:       fc,
		padder:   obfs.NewPadder(padMax),
		window:   windowBytes,
		streams:  make(map[uint32]*Stream),
		isClient: isClient,
		accept:   make(chan *Stream, 16),
		closed:   make(chan struct{}),
	}
	if isClient {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	go s.readLoop()
	return s
}

func (s *Session) writeFrame(cmd byte, id uint32, payload []byte) error {
	body := make([]byte, 5+len(payload))
	body[0] = cmd
	binary.BigEndian.PutUint32(body[1:5], id)
	copy(body[5:], payload)

	wrapped, err := obfs.Wrap(body, s.padder.Size())
	if err != nil {
		return err
	}
	s.wMu.Lock()
	defer s.wMu.Unlock()
	return s.fc.WriteRecord(wrapped)
}

func (s *Session) readLoop() {
	for {
		rec, err := s.fc.ReadRecord()
		if err != nil {
			s.closeWith(err)
			return
		}
		body, err := obfs.Unwrap(rec)
		if err != nil {
			s.closeWith(err)
			return
		}
		if len(body) < 5 {
			continue // padding-only / malformed; ignore
		}
		cmd := body[0]
		id := binary.BigEndian.Uint32(body[1:5])
		data := body[5:]

		switch cmd {
		case cmdSYN:
			if len(data) < 1 {
				continue
			}
			st := s.registerStream(id)
			st.Kind = data[0]
			st.dest = string(data[1:])
			select {
			case s.accept <- st:
			case <-s.closed:
				return
			}
		case cmdDATA:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				st.push(data) // never blocks; bounded by the sender's credit
			}
		case cmdWINDOW:
			if len(data) >= 4 {
				s.mu.Lock()
				st := s.streams[id]
				s.mu.Unlock()
				if st != nil {
					st.addCredit(int(binary.BigEndian.Uint32(data[:4])))
				}
			}
		case cmdFIN:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				st.closeBoth()
			}
		}
	}
}

func (s *Session) registerStream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.streams[id]; ok {
		return st
	}
	st := newStream(s, id)
	s.streams[id] = st
	return st
}

// Open creates a new outbound flow to dest. kind is KindTCP or KindUDP.
func (s *Session) Open(dest string, kind byte) (*Stream, error) {
	s.mu.Lock()
	if s.closeErr != nil {
		s.mu.Unlock()
		return nil, s.closeErr
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(s, id)
	st.Kind = kind
	st.dest = dest
	s.streams[id] = st
	s.mu.Unlock()

	payload := make([]byte, 1+len(dest))
	payload[0] = kind
	copy(payload[1:], dest)
	if err := s.writeFrame(cmdSYN, id, payload); err != nil {
		return nil, err
	}
	return st, nil
}

// Accept returns the next inbound stream (tunnel server side).
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.closed:
		return nil, s.closeErr
	}
}

func (s *Session) closeWith(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.closeErr = err
		for _, st := range s.streams {
			st.closeBoth()
		}
		s.mu.Unlock()
		close(s.closed)
	})
}

func (s *Session) Close() error {
	s.closeWith(errors.New("mux: session closed"))
	return s.fc.Close()
}

// Closed reports whether the session has been closed or its link has died.
func (s *Session) Closed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// StreamCount returns the number of active streams.
func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// ─────────────────────────── Stream ───────────────────────────

// Stream is one logical flow. For KindTCP it is an io.ReadWriteCloser byte
// stream with flow control; for KindUDP use ReadDatagram/WriteDatagram.
type Stream struct {
	s    *Session
	id   uint32
	dest string
	Kind byte

	// receive side
	rMu        sync.Mutex
	rCond      *sync.Cond
	rBuf       []byte
	rDgrams    [][]byte
	rClosed    bool
	rDeadline  time.Time // zero = no deadline (diagnostics only)
	pendingAck int       // bytes consumed but not yet granted back via WINDOW_UPDATE

	// send side (credit-based flow control)
	sMu        sync.Mutex
	sCond      *sync.Cond
	sendCredit int
	sClosed    bool
}

func newStream(s *Session, id uint32) *Stream {
	st := &Stream{s: s, id: id, sendCredit: s.window}
	st.rCond = sync.NewCond(&st.rMu)
	st.sCond = sync.NewCond(&st.sMu)
	return st
}

func (st *Stream) Dest() string { return st.dest }

// push delivers received DATA to the stream buffer. It never blocks: the peer
// is credit-limited, so rBuf can never exceed ~one window.
func (st *Stream) push(data []byte) {
	st.rMu.Lock()
	if st.Kind == KindUDP {
		if len(st.rDgrams) < 1024 { // bound the datagram queue
			cp := make([]byte, len(data))
			copy(cp, data)
			st.rDgrams = append(st.rDgrams, cp)
		}
	} else {
		st.rBuf = append(st.rBuf, data...)
	}
	st.rCond.Broadcast()
	st.rMu.Unlock()
}

func (st *Stream) addCredit(n int) {
	st.sMu.Lock()
	st.sendCredit += n
	st.sCond.Broadcast()
	st.sMu.Unlock()
}

// closeBoth closes receive and send sides and wakes anything waiting.
func (st *Stream) closeBoth() {
	st.rMu.Lock()
	st.rClosed = true
	st.rCond.Broadcast()
	st.rMu.Unlock()
	st.sMu.Lock()
	st.sClosed = true
	st.sCond.Broadcast()
	st.sMu.Unlock()
}

// closeRead closes only the receive side (kept for internal callers).
func (st *Stream) closeRead() { st.closeBoth() }

// SetReadDeadline bounds how long Read will block waiting for data. A zero time
// clears it. Intended for diagnostics (bench/diag) so a stalled tunnel reports
// instead of hanging; the normal data path leaves it unset.
func (st *Stream) SetReadDeadline(t time.Time) error {
	st.rMu.Lock()
	st.rDeadline = t
	st.rCond.Broadcast()
	st.rMu.Unlock()
	return nil
}

func (st *Stream) Read(p []byte) (int, error) {
	st.rMu.Lock()
	for len(st.rBuf) == 0 && !st.rClosed {
		if st.s.Closed() {
			st.rMu.Unlock()
			return 0, io.EOF
		}
		if !st.rDeadline.IsZero() {
			if !time.Now().Before(st.rDeadline) {
				st.rMu.Unlock()
				return 0, ErrReadTimeout
			}
			// Wake the cond when the deadline elapses so Wait doesn't block past it.
			timer := time.AfterFunc(time.Until(st.rDeadline), func() {
				st.rMu.Lock()
				st.rCond.Broadcast()
				st.rMu.Unlock()
			})
			st.rCond.Wait()
			timer.Stop()
		} else {
			st.rCond.Wait()
		}
	}
	if len(st.rBuf) == 0 {
		st.rMu.Unlock()
		return 0, io.EOF
	}
	n := copy(p, st.rBuf)
	st.rBuf = st.rBuf[n:]
	// Accumulate consumed bytes; grant the peer more credit once enough is
	// consumed. The threshold is capped at 64KB so that even if the two ends are
	// configured with different windows, the sender (whose credit = ITS window)
	// always receives updates before running out — i.e. no deadlock on mismatch.
	st.pendingAck += n
	ack := 0
	thresh := st.s.window / 2
	if thresh > 64*1024 {
		thresh = 64 * 1024
	}
	if st.pendingAck >= thresh {
		ack = st.pendingAck
		st.pendingAck = 0
	}
	st.rMu.Unlock()

	if ack > 0 {
		var cr [4]byte
		binary.BigEndian.PutUint32(cr[:], uint32(ack))
		_ = st.s.writeFrame(cmdWINDOW, st.id, cr[:])
	}
	return n, nil
}

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.sMu.Lock()
		for st.sendCredit <= 0 && !st.sClosed && !st.s.Closed() {
			st.sCond.Wait()
		}
		if st.sClosed || st.s.Closed() {
			st.sMu.Unlock()
			return total, io.ErrClosedPipe
		}
		n := len(p)
		if n > st.sendCredit {
			n = st.sendCredit
		}
		if n > obfs.MaxFramePayload-5 {
			n = obfs.MaxFramePayload - 5
		}
		st.sendCredit -= n
		st.sMu.Unlock()

		if err := st.s.writeFrame(cmdDATA, st.id, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (st *Stream) Close() error {
	st.closeBoth()
	return st.s.writeFrame(cmdFIN, st.id, nil)
}

// WriteDatagram sends one UDP datagram as a single framed unit (no flow
// control; UDP may drop). Oversized datagrams are rejected.
func (st *Stream) WriteDatagram(p []byte) error {
	if len(p) > obfs.MaxFramePayload-5 {
		return errors.New("mux: datagram too large")
	}
	return st.s.writeFrame(cmdDATA, st.id, p)
}

// ReadDatagram returns the next UDP datagram, preserving its boundary.
func (st *Stream) ReadDatagram() ([]byte, error) {
	st.rMu.Lock()
	for len(st.rDgrams) == 0 && !st.rClosed {
		st.rCond.Wait()
	}
	if len(st.rDgrams) > 0 {
		d := st.rDgrams[0]
		st.rDgrams = st.rDgrams[1:]
		st.rMu.Unlock()
		return d, nil
	}
	st.rMu.Unlock()
	return nil, io.EOF
}
