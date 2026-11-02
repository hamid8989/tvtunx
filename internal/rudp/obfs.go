package rudp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// Packet obfuscation: every UDP datagram is XORed with a keystream derived from
// the PSK and a per-packet random nonce (prepended in the clear). This hides the
// reliable-UDP header (conv/cmd/sn/una) so a DPI sees only high-entropy bytes
// with no stable structure to fingerprint, and it doubles as cheap auth: a peer
// without the PSK cannot produce a datagram that de-obfuscates to a valid header,
// so the server never promotes it past the (idle-reaped) per-address Conn. When
// PSK is empty (tests/local), obfuscation is a no-op.
//
// This is transport-shape hiding only; the tunnel's real confidentiality and
// authentication stay with the frame + handshake layers running on top of rudp.

const obfsNonce = 8

func keystream(psk, nonce []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	var ctr uint32
	var c [4]byte
	for len(out) < n {
		h := hmac.New(sha256.New, psk)
		h.Write(nonce)
		binary.BigEndian.PutUint32(c[:], ctr)
		h.Write(c[:])
		out = h.Sum(out)
		ctr++
	}
	return out[:n]
}

// obfuscate wraps a raw packet: nonce(8) || (packet XOR keystream). No-op if psk
// is empty.
func obfuscate(psk, pkt []byte) []byte {
	if len(psk) == 0 {
		return pkt
	}
	nonce := make([]byte, obfsNonce)
	_, _ = rand.Read(nonce)
	ks := keystream(psk, nonce, len(pkt))
	out := make([]byte, obfsNonce+len(pkt))
	copy(out, nonce)
	for i := range pkt {
		out[obfsNonce+i] = pkt[i] ^ ks[i]
	}
	return out
}

// deobfuscate reverses obfuscate. Returns nil if the datagram is too short. No-op
// (returns the input) if psk is empty.
func deobfuscate(psk, raw []byte) []byte {
	if len(psk) == 0 {
		return raw
	}
	if len(raw) < obfsNonce {
		return nil
	}
	nonce := raw[:obfsNonce]
	ct := raw[obfsNonce:]
	ks := keystream(psk, nonce, len(ct))
	body := make([]byte, len(ct))
	for i := range ct {
		body[i] = ct[i] ^ ks[i]
	}
	return body
}
