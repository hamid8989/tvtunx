// Package handshake performs a probe-resistant authenticated key exchange.
//
// Threat model:
//
//	An active prober (the censor) connects to the server and sends arbitrary
//	bytes, hoping the server replies in a way that identifies the tunnel. Our
//	defense: the client's very first message is authenticated with a
//	pre-shared key (PSK). If that authentication fails, the server does NOT
//	reply with any error — it keeps the socket open and silent (or serves a
//	decoy), exactly like a host with a closed application-layer service. A
//	prober therefore cannot distinguish our server from background noise.
//
// Flow:
//
//	client → server:  ephClientPub(32) || tag(16)
//	    tag = HMAC-like AEAD over a fixed label, keyed by PSK, with ephClientPub
//	    as associated data and a timestamp window to bound replay.
//	server → client:  ephServerPub(32) || confirm(16)
//	    only sent if the client tag verified.
//
// Both sides then derive directional keys via HKDF over the X25519 shared
// secret mixed with the PSK. No protocol version, no magic bytes, no TLS —
// the first 32 bytes are an ephemeral public key, which is indistinguishable
// from random to an observer who lacks the PSK.
package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// aeadOverhead is the GCM tag size, matching the frame layer.
const aeadOverhead = 16

// newAEAD builds AES-256-GCM from a 32-byte key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Keys is the output of a completed handshake.
type Keys struct {
	SendKey    []byte  // 32 bytes
	RecvKey    []byte  // 32 bytes
	SendLenKey [8]byte // length-prefix mask (our writes)
	RecvLenKey [8]byte // length-prefix mask (their writes)
}

const (
	pubLen    = 32
	tagLen    = aeadOverhead
	authMsg   = pubLen + tagLen
	replayWin = 90 * time.Second
)

var label = []byte("tvtunx/hs/v1") // used only as AEAD associated-data salt

// pskAEAD builds the key used to authenticate the opening message from the PSK.
func pskAEAD(psk []byte) ([]byte, error) {
	// Stretch the PSK to a 32-byte key; PSK may be any length.
	return hkdf.Key(sha256.New, psk, label, "psk-auth", 32)
}

// timeNonce encodes the current 30-second time bucket into a nonce so the
// server can bound replays to a window without storing state.
func timeNonce(bucket int64) []byte {
	var n [12]byte // GCM standard nonce size
	binary.BigEndian.PutUint64(n[4:], uint64(bucket))
	return n[:]
}

func bucketNow() int64 { return time.Now().Unix() / 30 }

// Client runs the initiator side over rw. Returns directional keys.
func Client(rw io.ReadWriter, psk []byte) (*Keys, error) {
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := eph.PublicKey().Bytes()

	key, err := pskAEAD(psk)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	// tag authenticates pub under the PSK, bound to the current time bucket.
	tag := aead.Seal(nil, timeNonce(bucketNow()), nil, pub)

	out := make([]byte, 0, authMsg)
	out = append(out, pub...)
	out = append(out, tag...)
	if _, err := rw.Write(out); err != nil {
		return nil, err
	}

	// Read server reply: ephServerPub || confirm.
	resp := make([]byte, authMsg)
	if _, err := io.ReadFull(rw, resp); err != nil {
		return nil, errors.New("handshake: no/short server reply (server may be silently rejecting)")
	}
	srvPub := resp[:pubLen]
	confirm := resp[pubLen:]

	// Verify server confirm (keyed by PSK, nonce = next bucket, AAD = srvPub).
	if _, err := aead.Open(nil, timeNonce(bucketNow()+1), confirm, srvPub); err != nil {
		if _, err2 := aead.Open(nil, timeNonce(bucketNow()), confirm, srvPub); err2 != nil {
			return nil, errors.New("handshake: server confirm failed")
		}
	}

	srvKey, err := curve.NewPublicKey(srvPub)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(srvKey)
	if err != nil {
		return nil, err
	}
	return deriveKeys(shared, psk, pub, srvPub, true)
}

// Server runs the responder side. If the client fails PSK auth, it returns
// (nil, ErrReject) and the caller MUST keep the connection open & silent (or
// hand it to a decoy) rather than closing with an error.
var ErrReject = errors.New("handshake: client rejected (stay silent)")

func Server(rw io.ReadWriter, psk []byte) (*Keys, error) {
	in := make([]byte, authMsg)
	if _, err := io.ReadFull(rw, in); err != nil {
		return nil, ErrReject
	}
	cliPub := in[:pubLen]
	cliTag := in[pubLen:]

	key, err := pskAEAD(psk)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	// Accept current or previous bucket (clock skew / in-flight), bounding replay.
	b := bucketNow()
	okAuth := false
	for _, cand := range []int64{b, b - 1, b - int64(replayWin/time.Second/30)} {
		if _, err := aead.Open(nil, timeNonce(cand), cliTag, cliPub); err == nil {
			okAuth = true
			break
		}
	}
	if !okAuth {
		return nil, ErrReject
	}

	curve := ecdh.X25519()
	cliKey, err := curve.NewPublicKey(cliPub)
	if err != nil {
		return nil, ErrReject
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	srvPub := eph.PublicKey().Bytes()
	confirm := aead.Seal(nil, timeNonce(b+1), nil, srvPub)

	out := make([]byte, 0, authMsg)
	out = append(out, srvPub...)
	out = append(out, confirm...)
	if _, err := rw.Write(out); err != nil {
		return nil, err
	}

	shared, err := eph.ECDH(cliKey)
	if err != nil {
		return nil, err
	}
	return deriveKeys(shared, psk, cliPub, srvPub, false)
}

// deriveKeys mixes the ECDH secret with the PSK and both ephemeral pubkeys via
// HKDF, then splits into directional keys. isClient decides which half is send.
func deriveKeys(shared, psk, cliPub, srvPub []byte, isClient bool) (*Keys, error) {
	salt := make([]byte, 0, len(cliPub)+len(srvPub))
	salt = append(salt, cliPub...)
	salt = append(salt, srvPub...)
	ikm := make([]byte, 0, len(shared)+len(psk))
	ikm = append(ikm, shared...)
	ikm = append(ikm, psk...)

	// Layout: c2sKey(32) s2cKey(32) c2sLen(8) s2cLen(8)
	buf, err := hkdf.Key(sha256.New, ikm, salt, string(label), 32+32+8+8)
	if err != nil {
		return nil, err
	}
	c2sKey := buf[0:32]
	s2cKey := buf[32:64]
	var c2sLen, s2cLen [8]byte
	copy(c2sLen[:], buf[64:72])
	copy(s2cLen[:], buf[72:80])

	k := &Keys{}
	if isClient {
		k.SendKey, k.RecvKey = c2sKey, s2cKey
		k.SendLenKey, k.RecvLenKey = c2sLen, s2cLen
	} else {
		k.SendKey, k.RecvKey = s2cKey, c2sKey
		k.SendLenKey, k.RecvLenKey = s2cLen, c2sLen
	}
	return k, nil
}
