package qmask

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestInitialRoundTrip builds a client Initial with a payload and parses it back
// using the public DCID-derived keys, verifying QUIC-standard interop: a DPI (or
// our exit) that knows only the DCID recovers the exact ClientHello bytes.
func TestInitialRoundTrip(t *testing.T) {
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	rand.Read(dcid)
	rand.Read(scid)

	// A realistic Initial payload: a CRYPTO frame-ish blob padded to QUIC's
	// 1200-byte minimum.
	payload := make([]byte, 1162) // +4 pn +16 tag + headers ≈ 1200
	rand.Read(payload[:200])

	pkt, err := BuildInitial(dcid, dcid, scid, nil, payload, 0, true)
	if err != nil {
		t.Fatalf("BuildInitial: %v", err)
	}
	if len(pkt) < 1200 {
		t.Logf("packet len %d (ok for test, real client pads to >=1200)", len(pkt))
	}
	// First byte must have the long-header + fixed bits set once protection is
	// removed, but on the wire the low bits are masked; just ensure 0x80 is set.
	if pkt[0]&0x80 == 0 {
		t.Fatalf("not a long-header packet: byte0=%#x", pkt[0])
	}

	gotDCID, gotSCID, gotToken, gotPayload, pn, err := ParseInitial(nil, pkt, true)
	if err != nil {
		t.Fatalf("ParseInitial: %v", err)
	}
	if !bytes.Equal(gotDCID, dcid) {
		t.Errorf("DCID mismatch: %x != %x", gotDCID, dcid)
	}
	if !bytes.Equal(gotSCID, scid) {
		t.Errorf("SCID mismatch: %x != %x", gotSCID, scid)
	}
	if len(gotToken) != 0 {
		t.Errorf("token should be empty, got %x", gotToken)
	}
	if pn != 0 {
		t.Errorf("pn mismatch: %d != 0", pn)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload mismatch: %d vs %d bytes", len(gotPayload), len(payload))
	}
}

// TestInitialWrongKeyDirection ensures the server-direction keys do not open a
// client packet (sanity that direction separation works).
func TestInitialWrongKeyDirection(t *testing.T) {
	dcid := make([]byte, 8)
	rand.Read(dcid)
	payload := make([]byte, 64)
	pkt, err := BuildInitial(dcid, dcid, dcid, nil, payload, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := ParseInitial(nil, pkt, false); err == nil {
		t.Fatal("server-direction parse of a client packet should fail")
	}
}

// TestVarint checks QUIC varint encode/decode across the size classes.
func TestVarint(t *testing.T) {
	for _, v := range []uint64{0, 1, 63, 64, 16383, 16384, 1 << 29, 1 << 30} {
		b := appendVarint(nil, v)
		got, n := readVarint(b)
		if n != len(b) || got != v {
			t.Errorf("varint %d: got %d (n=%d, len=%d)", v, got, n, len(b))
		}
	}
}
