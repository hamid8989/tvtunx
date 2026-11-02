package rudp

import "encoding/binary"

// This file exposes a minimal lower-level API so another package (internal/qmask)
// can run rudp's reliability core over a socket it owns and frames itself — e.g.
// dressing each datagram as a QUIC 1-RTT packet — instead of rudp's built-in UDP
// socket and PSK-XOR obfuscation. The reliability logic is reused unchanged.

// MinPacketLen is the smallest valid rudp datagram (header, no payload). A framing
// layer can use it to drop obviously-junk inbound datagrams before Inject.
const MinPacketLen = headerSize

// NewConn builds a reliable-UDP Conn over an arbitrary datagram carrier: `send`
// transmits one already-framed datagram to the peer, and the caller feeds inbound
// (de-framed) datagrams with Inject. The caller owns the socket and all framing;
// conv must match on both ends. Use this when a higher layer provides its own
// obfuscation/camouflage (qmask); for a plain UDP carrier use Dial/Listen.
func NewConn(cfg Config, conv uint32, send func([]byte) error) *Conn {
	if conv == 0 {
		conv = randConv()
	}
	return newConn(cfg, conv, send)
}

// Conv returns the connection's conversation id.
func (c *Conn) Conv() uint32 { return c.conv }

// Done returns a channel closed when the Conn is closed, so a framing layer can
// clean up its per-peer state.
func (c *Conn) Done() <-chan struct{} { return c.done }

// isClosed reports whether the Conn has been closed.
func (c *Conn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// Inject delivers one inbound datagram (already de-framed by the caller) to the
// Conn's receive path. Call it from the socket read loop. It drops the datagram
// rather than blocking if the Conn is closing.
func (c *Conn) Inject(pkt []byte) {
	select {
	case c.inbox <- pkt:
	case <-c.done:
	}
}

// PeekConv reads the conversation id from the front of a de-framed rudp datagram,
// for a listener that demultiplexes peers. ok is false if the datagram is too
// short to be valid.
func PeekConv(pkt []byte) (conv uint32, ok bool) {
	if len(pkt) < headerSize {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[0:4]), true
}
