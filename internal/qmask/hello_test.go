package qmask

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestClientHelloAuthRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	const sni = "www.google.com"

	msg, clientRandom := buildClientHello(sni, psk)

	gotSNI, gotRandom, ok, err := VerifyClientHello(msg, psk)
	if err != nil {
		t.Fatalf("VerifyClientHello: %v", err)
	}
	if !ok {
		t.Fatal("auth token did not verify with the correct PSK")
	}
	if gotSNI != sni {
		t.Errorf("SNI = %q, want %q", gotSNI, sni)
	}
	if !bytes.Equal(gotRandom, clientRandom) {
		t.Errorf("clientRandom mismatch")
	}
}

func TestClientHelloWrongPSK(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	msg, _ := buildClientHello("example.com", psk)

	wrong := make([]byte, 32)
	rand.Read(wrong)
	sni, _, ok, err := VerifyClientHello(msg, wrong)
	if err != nil {
		t.Fatalf("VerifyClientHello: %v", err)
	}
	if ok {
		t.Fatal("auth verified with the WRONG PSK — must not happen")
	}
	// SNI is still readable (as a DPI would read it) even though auth fails.
	if sni != "example.com" {
		t.Errorf("SNI = %q, want example.com", sni)
	}
}

// TestFullInitialMasquerade is the end-to-end camouflage path: the client builds
// a real QUIC Initial carrying the ClientHello; the exit parses it with only the
// public DCID keys (exactly what a DPI can do) and recovers the SNI + verifies
// the hidden auth.
func TestFullInitialMasquerade(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	const sni = "www.cloudflare.com"

	ch, clientRandom := buildClientHello(sni, psk)
	payload := WrapCryptoFrame(ch, 1162)

	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	rand.Read(dcid)
	rand.Read(scid)
	pkt, err := BuildInitial(dcid, dcid, scid, nil, payload, 0, true)
	if err != nil {
		t.Fatalf("BuildInitial: %v", err)
	}
	if len(pkt) < 1200 {
		t.Errorf("Initial is %d bytes; QUIC requires >= 1200", len(pkt))
	}

	// Exit / DPI side: derive keys from DCID, decrypt, read the ClientHello.
	_, _, _, gotPayload, _, err := ParseInitial(nil, pkt, true)
	if err != nil {
		t.Fatalf("ParseInitial: %v", err)
	}
	gotCH, err := UnwrapCryptoFrame(gotPayload)
	if err != nil {
		t.Fatalf("UnwrapCryptoFrame: %v", err)
	}
	gotSNI, gotRandom, ok, err := VerifyClientHello(gotCH, psk)
	if err != nil || !ok {
		t.Fatalf("VerifyClientHello: ok=%v err=%v", ok, err)
	}
	if gotSNI != sni {
		t.Errorf("SNI = %q, want %q", gotSNI, sni)
	}
	if !bytes.Equal(gotRandom, clientRandom) {
		t.Error("clientRandom mismatch through full path")
	}
}
