// Package frame is the encrypted record layer that sits on top of a raw TCP
// connection once the handshake has produced send/recv keys.
//
// Wire format of one record (everything after the handshake):
//
//	[ 2 bytes: encrypted length ][ N bytes: AEAD ciphertext ]
//
// The 2-byte length is itself obscured by XORing with a keystream byte pair
// derived from the record counter, so even the length prefix has no stable
// value a DPI engine can latch onto. The ciphertext is ChaCha20-Poly1305 over
// the obfs-wrapped (padded) plaintext, with the record counter as the nonce.
package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// aeadOverhead is the GCM authentication tag size.
const aeadOverhead = 16

const maxRecord = aeadOverhead + 2 + 16*1024 + 900 // AEAD tag + obfs hdr + payload + pad

// nonceSize is the GCM standard nonce size.
const nonceSize = 12

// newAEAD builds an AES-256-GCM AEAD from a 32-byte key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Conn wraps an io.ReadWriteCloser with the encrypted, length-obscured record
// layer. Separate keys and counters are used per direction.
type Conn struct {
	raw io.ReadWriteCloser

	wMu     sync.Mutex
	wAEAD   cipher.AEAD
	wCtr    uint64
	wLenKey [8]byte

	rMu     sync.Mutex
	rAEAD   cipher.AEAD
	rCtr    uint64
	rLenKey [8]byte
	rBuf    []byte // leftover decrypted bytes not yet consumed by Read
}

// NewConn builds a record layer. sendKey/recvKey are 32-byte ChaCha20 keys and
// lenKeys are 8-byte masks for the length prefix, all from the handshake.
func NewConn(raw io.ReadWriteCloser, sendKey, recvKey []byte, sendLenKey, recvLenKey [8]byte) (*Conn, error) {
	wa, err := newAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	ra, err := newAEAD(recvKey)
	if err != nil {
		return nil, err
	}
	return &Conn{
		raw:     raw,
		wAEAD:   wa,
		rAEAD:   ra,
		wLenKey: sendLenKey,
		rLenKey: recvLenKey,
	}, nil
}

func nonce(ctr uint64) []byte {
	var n [nonceSize]byte
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n[:]
}

// maskLen obscures/reveals the 2-byte length using two bytes of the per-record
// length key rotated by the counter. Cheap, keyed, and counter-dependent so the
// same length never encodes to the same two bytes twice.
func maskLen(l uint16, key [8]byte, ctr uint64) uint16 {
	k := uint16(key[ctr%8])<<8 | uint16(key[(ctr+1)%8])
	return l ^ k
}

// WriteRecord encrypts one already-obfs-wrapped body and frames it.
func (c *Conn) WriteRecord(body []byte) error {
	c.wMu.Lock()
	defer c.wMu.Unlock()

	ct := c.wAEAD.Seal(nil, nonce(c.wCtr), body, nil)
	if len(ct) > 0xFFFF {
		return errors.New("frame: record too large")
	}
	masked := maskLen(uint16(len(ct)), c.wLenKey, c.wCtr)

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], masked)
	if _, err := c.raw.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := c.raw.Write(ct); err != nil {
		return err
	}
	c.wCtr++
	return nil
}

// ReadRecord reads and decrypts exactly one record, returning its plaintext
// body (still obfs-wrapped; caller unwraps).
func (c *Conn) ReadRecord() ([]byte, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()

	var hdr [2]byte
	if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
		return nil, err
	}
	masked := binary.BigEndian.Uint16(hdr[:])
	clen := maskLen(masked, c.rLenKey, c.rCtr) // XOR is its own inverse
	if int(clen) > maxRecord || clen < aeadOverhead {
		return nil, errors.New("frame: implausible record length (torn stream or wrong key)")
	}

	ct := make([]byte, clen)
	if _, err := io.ReadFull(c.raw, ct); err != nil {
		return nil, err
	}
	pt, err := c.rAEAD.Open(nil, nonce(c.rCtr), ct, nil)
	if err != nil {
		return nil, errors.New("frame: AEAD auth failed")
	}
	c.rCtr++
	return pt, nil
}

func (c *Conn) Close() error { return c.raw.Close() }
