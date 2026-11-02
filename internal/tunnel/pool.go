package tunnel

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/local/tvtunx/internal/mux"
)

// SessionPool keeps a small, fixed set of tunnel sessions to the exit and
// multiplexes every flow (TCP connection or UDP source) over them as mux
// streams. This is what keeps memory bounded: without it, each new TCP
// connection and each new UDP source would open its own TLS session, which
// under real traffic (QUIC/DNS spraying source ports) exhausts RAM and the
// process is OOM-killed.
//
// Sessions are created lazily and replaced automatically when they die, so a
// dropped link self-heals on the next Stream() call.
//
// Rotation: Iranian ISPs commonly throttle a long-lived international TCP flow
// progressively — it starts fast and is shaped down the longer it lives. To
// counter that, when RotateSec > 0 the pool proactively retires each session
// once it reaches that age and replaces it with a fresh connection, so no flow
// lives long enough to be fully throttled. Rotation is staggered (at most one
// session retiring at a time) so the connection count to the foreign IP stays
// low, and a retired session is closed only after its streams drain (or a hard
// grace), so live traffic is not cut abruptly. This is purely relay-side and
// changes nothing on the wire, so it needs no matching change on the exit.
type pooledSession struct {
	sess   *mux.Session
	bornNS int64
}

type SessionPool struct {
	cfg         ClientConfig
	size        int
	rotateAfter time.Duration // 0 = rotation disabled

	mu    sync.Mutex
	slots []*pooledSession
	rr    uint64 // round-robin counter

	stop     chan struct{}
	stopOnce sync.Once
}

func NewSessionPool(cfg ClientConfig, size int) *SessionPool {
	if size < 1 {
		size = 1
	}
	p := &SessionPool{
		cfg:   cfg,
		size:  size,
		slots: make([]*pooledSession, size),
		stop:  make(chan struct{}),
	}
	if cfg.RotateSec > 0 {
		p.rotateAfter = time.Duration(cfg.RotateSec) * time.Second
		go p.rotator()
	}
	return p
}

// get returns a live session for the given slot, dialing/redialing if needed.
func (p *SessionPool) get(slot int) (*mux.Session, error) {
	p.mu.Lock()
	ps := p.slots[slot]
	p.mu.Unlock()
	if ps != nil && !ps.sess.Closed() {
		return ps.sess, nil
	}
	// Need a new session. Dial outside the lock (TLS handshake is slow).
	ns, err := dialSession(p.cfg)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	// Another goroutine may have dialed meanwhile; keep theirs, close ours.
	if p.slots[slot] != nil && !p.slots[slot].sess.Closed() {
		cur := p.slots[slot].sess
		p.mu.Unlock()
		ns.Close()
		return cur, nil
	}
	p.slots[slot] = &pooledSession{sess: ns, bornNS: time.Now().UnixNano()}
	p.mu.Unlock()
	return ns, nil
}

// OpenStream picks a session (round-robin) and opens a stream on it, retrying
// once on a dead session so a silently-dropped link doesn't fail the flow.
func (p *SessionPool) OpenStream(dest string, kind byte) (*mux.Stream, error) {
	slot := int(atomic.AddUint64(&p.rr, 1) % uint64(p.size))
	for attempt := 0; attempt < 2; attempt++ {
		s, err := p.get(slot)
		if err != nil {
			return nil, err
		}
		st, err := s.Open(dest, kind)
		if err == nil {
			return st, nil
		}
		// Session was dead; drop it so get() redials, then retry once.
		p.mu.Lock()
		if p.slots[slot] != nil && p.slots[slot].sess == s {
			p.slots[slot] = nil
		}
		p.mu.Unlock()
		s.Close()
	}
	return nil, &simpleErr{"pool: could not open stream after retry"}
}

// rotator periodically retires aged sessions, at most one at a time so the
// number of live connections to the exit IP barely changes.
func (p *SessionPool) rotator() {
	// Check often enough that every slot gets a turn within one rotation period.
	interval := p.rotateAfter / time.Duration(p.size+1)
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.rotateOneExpired()
		}
	}
}

// rotateOneExpired retires the single oldest expired session (if any).
func (p *SessionPool) rotateOneExpired() {
	now := time.Now().UnixNano()
	oldest := -1
	var oldestBorn int64
	p.mu.Lock()
	for i, ps := range p.slots {
		if ps == nil || ps.sess.Closed() {
			continue
		}
		age := now - ps.bornNS
		if age < int64(p.rotateAfter) {
			continue
		}
		if oldest == -1 || ps.bornNS < oldestBorn {
			oldest = i
			oldestBorn = ps.bornNS
		}
	}
	var old *pooledSession
	if oldest != -1 {
		old = p.slots[oldest]
	}
	p.mu.Unlock()
	if oldest == -1 {
		return
	}

	// Dial the replacement outside the lock.
	ns, err := dialSession(p.cfg)
	if err != nil {
		return // keep the old session if we can't replace it
	}
	p.mu.Lock()
	if p.slots[oldest] == old { // still the same session
		p.slots[oldest] = &pooledSession{sess: ns, bornNS: time.Now().UnixNano()}
		p.mu.Unlock()
		go p.drainClose(old.sess)
	} else {
		p.mu.Unlock()
		ns.Close() // someone else already replaced it
	}
}

// drainClose closes a retired session once its streams finish, or after a hard
// grace period, so live flows migrate to the fresh session instead of dropping.
func (p *SessionPool) drainClose(s *mux.Session) {
	deadline := time.Now().Add(120 * time.Second)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			s.Close()
			return
		case <-t.C:
			if s.StreamCount() == 0 || time.Now().After(deadline) {
				s.Close()
				return
			}
		}
	}
}

func (p *SessionPool) Close() {
	p.stopOnce.Do(func() { close(p.stop) })
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, ps := range p.slots {
		if ps != nil {
			ps.sess.Close()
			p.slots[i] = nil
		}
	}
}
