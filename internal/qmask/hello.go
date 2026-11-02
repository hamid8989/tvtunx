package qmask

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// This file hand-builds the TLS 1.3 ClientHello that rides inside the QUIC
// Initial, plus the CRYPTO-frame framing that wraps it. The ClientHello is
// Chrome-flavoured (GREASE first, the three TLS 1.3 AEAD suites, h3 ALPN, a
// quic_transport_parameters extension) and carries a real SNI, so a DPI that
// decrypts the Initial (it can — the keys come from the public DCID) sees an
// ordinary QUIC/HTTP-3 handshake to an allowed site and lets it pass.
//
// Our client is told apart from a real browser by a PSK-keyed auth token hidden
// as a GREASE-shaped QUIC transport parameter: to a DPI it is indistinguishable
// from the random GREASE value Chrome itself sends, but the exit can recompute
// and verify it. No external TLS library is needed — everything here is stdlib,
// which is what lets v1.0.0 ship with zero dependencies.

const (
	tlsClientHello = 0x01
	tlsVersion12   = 0x0303
	tlsVersion13   = 0x0304

	extServerName        = 0x0000
	extSupportedGroups   = 0x000a
	extALPN              = 0x0010
	extSignatureAlgs     = 0x000d
	extSupportedVersions = 0x002b
	extPSKModes          = 0x002d
	extKeyShare          = 0x0033
	extQUICTransport     = 0x0039

	groupX25519 = 0x001d

	// greaseAuthParam is a QUIC transport-parameter id of the reserved form
	// 31*N+27 (RFC 9000 §18.1), which peers must ignore — real stacks use these
	// for GREASE. We overload one to carry the auth token; it looks like GREASE.
	greaseAuthParam = 31*1041 + 27 // = 32298
)

var authLabel = []byte("tvtunx/v1 quic-masquerade auth")

// authToken = HMAC-SHA256(psk, authLabel || clientRandom)[:16].
func authToken(psk, clientRandom []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(authLabel)
	m.Write(clientRandom)
	return m.Sum(nil)[:16]
}

// grease returns a GREASE value (0x?a?a, both bytes equal, low nibble 0xa) as
// browsers use to exercise peers' unknown-value handling (RFC 8701).
func grease(b byte) uint16 { return uint16(b)<<8 | uint16(b) }

// buildClientHello returns (clientHelloMessage, clientRandom). The ClientHello
// embeds `sni` and a PSK auth token derived from the random it generates.
func buildClientHello(sni string, psk []byte) (msg, clientRandom []byte) {
	clientRandom = make([]byte, 32)
	rand.Read(clientRandom)
	sid := make([]byte, 32) // QUIC/Chrome: 32-byte random legacy_session_id
	rand.Read(sid)

	var b []byte
	b = append(b, byte(tlsVersion12>>8), byte(tlsVersion12&0xff))
	b = append(b, clientRandom...)
	b = append(b, byte(len(sid)))
	b = append(b, sid...)

	// cipher_suites: GREASE + the three TLS 1.3 suites
	suites := []uint16{grease(0x0a), 0x1301, 0x1302, 0x1303}
	b = appendU16Vec16(b, suites)

	// legacy_compression_methods: null only
	b = append(b, 0x01, 0x00)

	// extensions
	ext := buildExtensions(sni, clientRandom, psk, sid)
	b = append(b, byte(len(ext)>>8), byte(len(ext)))
	b = append(b, ext...)

	// wrap as a handshake message: type(1) + length(3)
	msg = make([]byte, 0, 4+len(b))
	msg = append(msg, tlsClientHello)
	msg = append(msg, byte(len(b)>>16), byte(len(b)>>8), byte(len(b)))
	msg = append(msg, b...)
	return msg, clientRandom
}

func buildExtensions(sni string, clientRandom, psk, scid []byte) []byte {
	var e []byte

	// GREASE (empty)
	e = appendExt(e, grease(0x1a), nil)

	// server_name
	var sn []byte
	sn = append(sn, 0x00)                                   // name_type host_name
	sn = append(sn, byte(len(sni)>>8), byte(len(sni)))      // name length
	sn = append(sn, sni...)
	snList := append([]byte{byte(len(sn) >> 8), byte(len(sn))}, sn...)
	e = appendExt(e, extServerName, snList)

	// supported_groups: GREASE + x25519
	e = appendExt(e, extSupportedGroups, u16Vec16Body([]uint16{grease(0x2a), groupX25519}))

	// ALPN: h3
	alpn := []byte{0x00, 0x00} // list length placeholder
	proto := []byte("h3")
	body := append([]byte{byte(len(proto))}, proto...)
	alpn = append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)
	e = appendExt(e, extALPN, alpn)

	// signature_algorithms (a plausible Chrome set)
	sigAlgs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	e = appendExt(e, extSignatureAlgs, u16Vec16Body(sigAlgs))

	// supported_versions: GREASE + TLS 1.3  (vector with 1-byte length)
	sv := []uint16{grease(0x3a), tlsVersion13}
	svb := []byte{byte(len(sv) * 2)}
	for _, v := range sv {
		svb = append(svb, byte(v>>8), byte(v))
	}
	e = appendExt(e, extSupportedVersions, svb)

	// psk_key_exchange_modes: psk_dhe_ke(1)
	e = appendExt(e, extPSKModes, []byte{0x01, 0x01})

	// key_share: x25519 with 32 random bytes (structure-valid; curve point not
	// validated by passive DPI, and we never complete this TLS handshake)
	ks := make([]byte, 32)
	rand.Read(ks)
	ksEntry := []byte{byte(groupX25519 >> 8), byte(groupX25519), 0x00, 0x20}
	ksEntry = append(ksEntry, ks...)
	ksBody := append([]byte{byte(len(ksEntry) >> 8), byte(len(ksEntry))}, ksEntry...)
	e = appendExt(e, extKeyShare, ksBody)

	// quic_transport_parameters, carrying the hidden auth token
	e = appendExt(e, extQUICTransport, buildTransportParams(clientRandom, psk, scid))

	// trailing GREASE
	e = appendExt(e, grease(0x4a), nil)
	return e
}

// buildTransportParams emits a believable set of QUIC transport parameters plus
// the GREASE-shaped auth parameter.
func buildTransportParams(clientRandom, psk, scid []byte) []byte {
	var p []byte
	p = tp(p, 0x01, varintBytes(30000))      // max_idle_timeout (ms)
	p = tp(p, 0x03, varintBytes(1472))       // max_udp_payload_size
	p = tp(p, 0x04, varintBytes(15728640))   // initial_max_data
	p = tp(p, 0x05, varintBytes(6291456))    // initial_max_stream_data_bidi_local
	p = tp(p, 0x06, varintBytes(6291456))    // initial_max_stream_data_bidi_remote
	p = tp(p, 0x07, varintBytes(6291456))    // initial_max_stream_data_uni
	p = tp(p, 0x08, varintBytes(100))        // initial_max_streams_bidi
	p = tp(p, 0x09, varintBytes(100))        // initial_max_streams_uni
	p = tp(p, 0x0f, scid)                    // initial_source_connection_id
	// GREASE-shaped auth param (reserved id, ignored by real stacks)
	p = tp(p, greaseAuthParam, authToken(psk, clientRandom))
	return p
}

// tp appends one transport parameter: id(varint) len(varint) value.
func tp(b []byte, id uint64, val []byte) []byte {
	b = appendVarint(b, id)
	b = appendVarint(b, uint64(len(val)))
	return append(b, val...)
}

func varintBytes(v uint64) []byte { return appendVarint(nil, v) }

// appendExt appends one TLS extension: type(2) len(2) body.
func appendExt(b []byte, typ uint16, body []byte) []byte {
	b = append(b, byte(typ>>8), byte(typ))
	b = append(b, byte(len(body)>>8), byte(len(body)))
	return append(b, body...)
}

// appendU16Vec16 appends a <2..2^16-2> vector of uint16 with a 2-byte length.
func appendU16Vec16(b []byte, v []uint16) []byte {
	b = append(b, byte(len(v)*2>>8), byte(len(v)*2))
	for _, x := range v {
		b = append(b, byte(x>>8), byte(x))
	}
	return b
}

func u16Vec16Body(v []uint16) []byte {
	return appendU16Vec16(nil, v)
}

// ───────────────────────── parse side (exit) ─────────────────────────

// VerifyClientHello parses a ClientHello handshake message, extracts the SNI and
// the hidden auth param, and checks the PSK token. It returns the SNI, the
// clientRandom (for replay tracking) and ok=true only if the token verifies.
func VerifyClientHello(msg, psk []byte) (sni string, clientRandom []byte, ok bool, err error) {
	if len(msg) < 4 || msg[0] != tlsClientHello {
		return "", nil, false, errors.New("qmask: not a ClientHello")
	}
	body := msg[4:]
	off := 2 // legacy_version
	if off+32 > len(body) {
		return "", nil, false, errShort
	}
	clientRandom = append([]byte(nil), body[off:off+32]...)
	off += 32
	if off >= len(body) {
		return "", nil, false, errShort
	}
	sidLen := int(body[off])
	off += 1 + sidLen
	if off+2 > len(body) {
		return "", nil, false, errShort
	}
	csLen := int(body[off])<<8 | int(body[off+1])
	off += 2 + csLen
	if off >= len(body) {
		return "", nil, false, errShort
	}
	cmLen := int(body[off])
	off += 1 + cmLen
	if off+2 > len(body) {
		return "", nil, false, errShort
	}
	extLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	if off+extLen > len(body) {
		return "", nil, false, errShort
	}
	ext := body[off : off+extLen]

	var gotAuth []byte
	for len(ext) >= 4 {
		typ := uint16(ext[0])<<8 | uint16(ext[1])
		l := int(ext[2])<<8 | int(ext[3])
		if 4+l > len(ext) {
			break
		}
		val := ext[4 : 4+l]
		switch typ {
		case extServerName:
			sni = parseSNI(val)
		case extQUICTransport:
			gotAuth = findAuthParam(val)
		}
		ext = ext[4+l:]
	}
	if gotAuth == nil {
		return sni, clientRandom, false, nil
	}
	want := authToken(psk, clientRandom)
	ok = hmac.Equal(gotAuth, want)
	return sni, clientRandom, ok, nil
}

func parseSNI(val []byte) string {
	if len(val) < 2 {
		return ""
	}
	list := val[2:]
	if len(list) < 3 {
		return ""
	}
	// name_type(1) + length(2) + host
	nl := int(list[1])<<8 | int(list[2])
	if 3+nl > len(list) {
		return ""
	}
	return string(list[3 : 3+nl])
}

func findAuthParam(val []byte) []byte {
	for len(val) > 0 {
		id, n := readVarint(val)
		if n == 0 {
			return nil
		}
		val = val[n:]
		l, n2 := readVarint(val)
		if n2 == 0 || int(l)+n2 > len(val)+n2 {
			return nil
		}
		val = val[n2:]
		if int(l) > len(val) {
			return nil
		}
		pv := val[:l]
		if id == greaseAuthParam {
			return pv
		}
		val = val[l:]
	}
	return nil
}

// ───────────────────────── CRYPTO frame + Initial payload ─────────────────────────

// WrapCryptoFrame builds the Initial packet payload: a CRYPTO frame (type 0x06,
// offset 0) containing the handshake bytes, padded with PADDING (0x00) so the
// whole Initial reaches QUIC's 1200-byte minimum. `overhead` is the bytes the
// long header + tag will add, so the caller gets a payload of the right size.
func WrapCryptoFrame(handshake []byte, padTo int) []byte {
	var f []byte
	f = append(f, 0x06)                          // CRYPTO frame type
	f = appendVarint(f, 0)                        // offset
	f = appendVarint(f, uint64(len(handshake)))  // length
	f = append(f, handshake...)
	for len(f) < padTo {
		f = append(f, 0x00) // PADDING frames
	}
	return f
}

// UnwrapCryptoFrame extracts the handshake bytes from an Initial payload,
// skipping PADDING and ACK frames. Only the first CRYPTO frame is returned.
func UnwrapCryptoFrame(payload []byte) ([]byte, error) {
	i := 0
	for i < len(payload) {
		switch payload[i] {
		case 0x00: // PADDING
			i++
		case 0x01: // PING
			i++
		case 0x02, 0x03: // ACK (we don't expect these in a client Initial)
			return nil, errors.New("qmask: unexpected ACK frame")
		case 0x06: // CRYPTO
			i++
			_, n := readVarint(payload[i:]) // offset
			if n == 0 {
				return nil, errShort
			}
			i += n
			l, n2 := readVarint(payload[i:])
			if n2 == 0 {
				return nil, errShort
			}
			i += n2
			if i+int(l) > len(payload) {
				return nil, errShort
			}
			return payload[i : i+int(l)], nil
		default:
			return nil, errors.New("qmask: unexpected frame type")
		}
	}
	return nil, errors.New("qmask: no CRYPTO frame")
}

var _ = binary.BigEndian
