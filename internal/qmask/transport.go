package qmask

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/local/tvtunx/internal/rudp"
)

// transport.go ties the QUIC-Initial masquerade (initial.go + hello.go) to the
// reliable-UDP carrier (internal/rudp):
//
//   1. The client sends one real QUIC Initial carrying a Chrome ClientHello with
//      a real SNI and a hidden PSK auth token (looks like HTTP/3 to a DPI).
//   2. The exit decrypts it with the public DCID keys — exactly as a DPI would —
//      reads the SNI, and verifies the auth token. A real browser or an active
//      prober fails the token and gets no reply (a dead QUIC endpoint).
//   3. The exit replies with its own QUIC Initial carrying a confirm token, so
//      the client knows it reached a genuine exit.
//   4. Both switch to rudp for data, dressing every datagram as a QUIC 1-RTT
//      short-header packet. The flow stays UDP to one 4-tuple, consistent with a
//      live QUIC session, and gains rudp's loss-tolerance.
//
// rudp handles reliability only; all confidentiality/camouflage for the data
// phase lives in the short-header framing here (a PSK-keyed stream cipher).

const (
	cidLen           = 8
	handshakeTimeout = 5 * time.Second
	handshakeRetries = 3
)

// Config configures a reality-udp endpoint.
type Config struct {
	SNI         string        // the real site name to show in the ClientHello
	PSK         []byte        // shared secret (auth + data-phase key)
	TargetMbit  int           // rudp pacing target (0 = window-limited)
	IdleTimeout time.Duration // rudp idle close
}

func (cfg Config) rudpConfig(conv uint32) rudp.Config {
	return rudp.Config{Conv: conv, TargetMbit: cfg.TargetMbit, IdleTimeout: cfg.IdleTimeout}
	// No rudp.PSK: qmask frames/obfuscates datagrams itself; rudp sees plaintext.
}

// ───────────────────────── data-phase key + framing ─────────────────────────

func dataKeyFrom(psk, clientRandom []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("tvtunx/v1 quic-masquerade data"))
	m.Write(clientRandom)
	return m.Sum(nil)
}

func confirmToken(psk, clientRandom []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("tvtunx/v1 quic-masquerade confirm"))
	m.Write(clientRandom)
	return m.Sum(nil)[:16]
}

// xorStream applies a PSK-keyed HMAC-CTR keystream in place.
func xorStream(key, nonce, buf []byte) {
	var block []byte
	bi := 0
	var ctr uint32
	for i := range buf {
		if bi == 0 || bi >= len(block) {
			m := hmac.New(sha256.New, key)
			m.Write(nonce)
			var c [4]byte
			binary.BigEndian.PutUint32(c[:], ctr)
			m.Write(c[:])
			block = m.Sum(nil)
			ctr++
			bi = 0
		}
		buf[i] ^= block[bi]
		bi++
	}
}

// peerFrame dresses rudp datagrams as QUIC 1-RTT short-header packets and back.
// peerCID is the connection id we address packets TO (the peer's chosen CID).
type peerFrame struct {
	peerCID []byte
	dataKey []byte
}

func (p *peerFrame) wrap(pkt []byte) []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	out := make([]byte, 0, 1+cidLen+8+len(pkt))
	// short header: fixed bit (0x40) set, long-header bit (0x80) clear; the rest
	// (spin/key-phase/pn-len) is opaque to a DPI without 1-RTT keys, so vary it.
	out = append(out, 0x40|(nonce[0]&0x37))
	out = append(out, p.peerCID...)
	out = append(out, nonce...)
	body := append([]byte(nil), pkt...)
	xorStream(p.dataKey, nonce, body)
	return append(out, body...)
}

func (p *peerFrame) unwrap(raw []byte) []byte {
	const hdr = 1 + cidLen + 8
	if len(raw) < hdr+rudp.MinPacketLen || raw[0]&0x80 != 0 {
		return nil
	}
	nonce := raw[1+cidLen : 1+cidLen+8]
	body := append([]byte(nil), raw[hdr:]...)
	xorStream(p.dataKey, nonce, body)
	return body
}

func rand8() []byte {
	b := make([]byte, cidLen)
	rand.Read(b)
	return b
}

// ───────────────────────── client ─────────────────────────

// Dial performs the masquerade handshake to addr and returns a net.Conn (the
// reliable-UDP stream) ready for the tunnel's own handshake/mux stack.
func Dial(addr string, cfg Config) (net.Conn, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		return nil, err
	}

	dcid := rand8() // client's original DCID = key CID
	scid := rand8() // client's source CID
	ch, clientRandom := buildClientHello(cfg.SNI, cfg.PSK)
	initial, err := BuildInitial(dcid, dcid, scid, nil, WrapCryptoFrame(ch, 1162), 0, true)
	if err != nil {
		sock.Close()
		return nil, err
	}

	buf := make([]byte, 65535)
	var serverCID []byte
	for attempt := 0; attempt < handshakeRetries; attempt++ {
		if _, err := sock.Write(initial); err != nil {
			sock.Close()
			return nil, err
		}
		sock.SetReadDeadline(time.Now().Add(handshakeTimeout))
		n, err := sock.Read(buf)
		if err != nil {
			continue // timeout: retransmit the Initial
		}
		if buf[0]&0x80 == 0 {
			continue // not a long-header reply; ignore
		}
		_, pscid, _, rpayload, _, perr := ParseInitial(dcid, buf[:n], false)
		if perr != nil {
			continue
		}
		confirm, cerr := UnwrapCryptoFrame(rpayload)
		if cerr != nil || !hmac.Equal(firstN(confirm, 16), confirmToken(cfg.PSK, clientRandom)) {
			continue
		}
		serverCID = pscid
		break
	}
	if serverCID == nil {
		sock.Close()
		return nil, errors.New("qmask: handshake failed (no valid exit reply)")
	}
	sock.SetReadDeadline(time.Time{})

	frame := &peerFrame{peerCID: serverCID, dataKey: dataKeyFrom(cfg.PSK, clientRandom)}
	conn := rudp.NewConn(cfg.rudpConfig(0), 0, func(b []byte) error {
		_, e := sock.Write(frame.wrap(b))
		return e
	})
	go func() {
		rb := make([]byte, 65535)
		for {
			n, err := sock.Read(rb)
			if err != nil {
				conn.Close()
				sock.Close()
				return
			}
			if body := frame.unwrap(rb[:n]); body != nil {
				conn.Inject(body)
			}
		}
	}()
	return conn, nil
}

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// ───────────────────────── server ─────────────────────────

type peerState struct {
	frame        *peerFrame
	conn         *rudp.Conn
	reply        []byte // cached reply Initial, resent on a retransmitted client Initial
	clientRandom []byte
}

// Listener accepts reality-udp connections on one UDP socket.
type Listener struct {
	sock   *net.UDPConn
	cfg    Config
	accept chan net.Conn

	mu     sync.Mutex
	peers  map[string]*peerState
	closed chan struct{}
	once   sync.Once
	replay *replayCache
}

// Listen binds a UDP socket and serves the masquerade handshake + rudp.
func Listen(addr string, cfg Config) (*Listener, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		sock:   sock,
		cfg:    cfg,
		accept: make(chan net.Conn, 16),
		peers:  make(map[string]*peerState),
		closed: make(chan struct{}),
		replay: newReplayCache(2 * time.Minute),
	}
	go l.readLoop()
	return l, nil
}

func (l *Listener) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := l.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		key := raddr.String()
		pkt := append([]byte(nil), buf[:n]...)
		if pkt[0]&0x80 != 0 {
			l.handleInitial(pkt, raddr, key)
			continue
		}
		l.handleData(pkt, raddr, key)
	}
}

func (l *Listener) handleInitial(pkt []byte, raddr *net.UDPAddr, key string) {
	// Retransmitted Initial from a peer we already accepted: resend the reply.
	l.mu.Lock()
	if ps := l.peers[key]; ps != nil && ps.reply != nil {
		reply := ps.reply
		l.mu.Unlock()
		l.sock.WriteToUDP(reply, raddr)
		return
	}
	l.mu.Unlock()

	_, scid, _, payload, _, err := ParseInitial(nil, pkt, true)
	if err != nil {
		return // not a valid QUIC v1 Initial — ignore
	}
	dcid := initialDCID(pkt) // client's original DCID (= key CID) from the header
	ch, err := UnwrapCryptoFrame(payload)
	if err != nil {
		return
	}
	sni, clientRandom, ok, err := VerifyClientHello(ch, l.cfg.PSK)
	if err != nil || !ok {
		return // real browser / prober — stay silent (looks like a dead endpoint)
	}
	// When the exit pins an SNI, the client's ClientHello SNI must match it — the
	// same shared parameter both ends configure in classic REALITY. Empty = accept
	// any (the client alone decides the disguise site).
	if l.cfg.SNI != "" && sni != l.cfg.SNI {
		return
	}
	if l.replay.seenAndRecord(clientRandom) {
		return // replayed Initial captured by a prober
	}

	serverCID := rand8()
	reply, err := BuildInitial(dcid, scid, serverCID, nil,
		WrapCryptoFrame(confirmToken(l.cfg.PSK, clientRandom), 0), 0, false)
	if err != nil {
		return
	}
	frame := &peerFrame{peerCID: scid, dataKey: dataKeyFrom(l.cfg.PSK, clientRandom)}

	l.mu.Lock()
	l.peers[key] = &peerState{frame: frame, reply: reply, clientRandom: clientRandom}
	l.mu.Unlock()
	l.sock.WriteToUDP(reply, raddr)
}

func (l *Listener) handleData(pkt []byte, raddr *net.UDPAddr, key string) {
	l.mu.Lock()
	ps := l.peers[key]
	l.mu.Unlock()
	if ps == nil {
		return // data from an unauthenticated peer — drop
	}
	body := ps.frame.unwrap(pkt)
	if body == nil {
		return
	}
	l.mu.Lock()
	if ps.conn == nil {
		conv, ok := rudp.PeekConv(body)
		if !ok {
			l.mu.Unlock()
			return
		}
		ra := raddr
		frame := ps.frame
		ps.conn = rudp.NewConn(l.cfg.rudpConfig(conv), conv, func(b []byte) error {
			_, e := l.sock.WriteToUDP(frame.wrap(b), ra)
			return e
		})
		conn := ps.conn
		go func(k string, cc *rudp.Conn) {
			<-cc.Done()
			l.mu.Lock()
			if p := l.peers[k]; p != nil && p.conn == cc {
				delete(l.peers, k)
			}
			l.mu.Unlock()
		}(key, conn)
		l.mu.Unlock()
		select {
		case l.accept <- conn:
		case <-l.closed:
		}
		conn.Inject(body)
		return
	}
	conn := ps.conn
	l.mu.Unlock()
	conn.Inject(body)
}

// Accept returns the next established reality-udp connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, errors.New("qmask: listener closed")
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.sock.Close()
}

func (l *Listener) Addr() net.Addr { return l.sock.LocalAddr() }

// initialDCID returns the DCID field of a long-header packet (the client's
// original DCID, used as the Initial key CID), or nil if malformed.
func initialDCID(pkt []byte) []byte {
	if len(pkt) < 6 {
		return nil
	}
	dl := int(pkt[5])
	if 6+dl > len(pkt) {
		return nil
	}
	return pkt[6 : 6+dl]
}
