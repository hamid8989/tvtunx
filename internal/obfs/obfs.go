// Package obfs implements the length-obfuscation and padding layer.
//
// Design goals:
//   - No fixed bytes anywhere on the wire. The first bytes a passive observer
//     sees are ciphertext/random, never a magic header.
//   - Each frame carries a random amount of padding so that payload lengths do
//     not form a stable fingerprint for traffic analysis.
//   - Length prefixes themselves are encrypted (handled by the frame package),
//     so this package only decides *how much* padding to add and enforces caps.
package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
)

const (
	// MaxFramePayload caps a single logical frame's plaintext (before padding).
	// Largest plaintext payload in a single frame.
	MaxFramePayload = 16 * 1024

	// MaxPadding is the largest random pad we append to any frame.
	MaxPadding = 900
)

// Padder decides padding sizes. It is deliberately simple and swappable so the
// shaping policy can evolve without touching the framing/crypto code.
type Padder struct {
	// Max padding bytes to append. 0 disables padding.
	Max int
	// rng is a non-cryptographic PRNG; padding size secrecy is not required,
	// only unpredictability of the *pattern* to a passive observer.
	rng *mrand.Rand
}

// NewPadder seeds a padder from the crypto RNG so two endpoints don't share a
// predictable sequence.
func NewPadder(max int) *Padder {
	if max < 0 {
		max = 0
	}
	if max > MaxPadding {
		max = MaxPadding
	}
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	return &Padder{
		Max: max,
		rng: mrand.New(mrand.NewChaCha8(seed)),
	}
}

// Size returns a padding length in [0, Max]. We bias toward small pads most of
// the time but occasionally emit a large one, which flattens the length
// distribution better than a uniform draw.
func (p *Padder) Size() int {
	if p.Max == 0 {
		return 0
	}
	// 80% small pad, 20% full-range pad.
	if p.rng.IntN(100) < 80 {
		return p.rng.IntN(p.Max/4 + 1)
	}
	return p.rng.IntN(p.Max + 1)
}

// wrap builds the padded plaintext body: [2-byte real len][real][pad].
// The caller encrypts the whole thing, so the length field is never visible.
func Wrap(payload []byte, padBytes int) ([]byte, error) {
	if len(payload) > MaxFramePayload {
		return nil, errors.New("obfs: payload exceeds MaxFramePayload")
	}
	out := make([]byte, 2+len(payload)+padBytes)
	binary.BigEndian.PutUint16(out[:2], uint16(len(payload)))
	copy(out[2:], payload)
	if padBytes > 0 {
		// Padding content is random so it carries no exploitable structure.
		_, _ = rand.Read(out[2+len(payload):])
	}
	return out, nil
}

// Unwrap reverses Wrap: given decrypted body, return the real payload slice.
func Unwrap(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint16(body[:2]))
	if 2+n > len(body) {
		return nil, errors.New("obfs: declared length exceeds body")
	}
	return body[2 : 2+n], nil
}
