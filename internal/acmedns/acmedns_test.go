package acmedns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCloudflareProvider(t *testing.T) {
	var created, deleted bool
	mux := http.NewServeMux()
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			t.Errorf("missing bearer token")
		}
		if r.URL.Query().Get("name") != "example.com" {
			t.Errorf("zone query = %q", r.URL.Query().Get("name"))
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone1"}}})
	})
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		created = true
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["type"] != "TXT" || body["name"] != "_acme-challenge.t.example.com" || body["content"] != "val123" {
			t.Errorf("bad record body: %v", body)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "rec1"}})
	})
	mux.HandleFunc("/zones/zone1/dns_records/rec1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "rec1"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := &CloudflareProvider{Token: "tok123", Zone: "example.com", APIBase: srv.URL, Client: srv.Client()}
	if err := p.Present("_acme-challenge.t.example.com", "val123"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !created {
		t.Fatal("record not created")
	}
	if err := p.CleanUp("_acme-challenge.t.example.com", "val123"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if !deleted {
		t.Fatal("record not deleted")
	}
}

func TestCertSaveLoadAndRenew(t *testing.T) {
	dir := t.TempDir()
	// make a self-signed cert as if obtained, write in the expected filenames.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "*.t.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(80 * 24 * time.Hour),
		DNSNames: []string{"*.t.example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	savePEMChain(filepath.Join(dir, certFile), [][]byte{der})
	saveECKey(filepath.Join(dir, keyFile), key)

	c, err := LoadCert(dir)
	if err != nil {
		t.Fatalf("LoadCert: %v", err)
	}
	if c.Leaf == nil || c.Leaf.Subject.CommonName != "*.t.example.com" {
		t.Fatalf("leaf not parsed / wrong CN")
	}
	if NeedsRenew(dir) {
		t.Fatalf("cert valid 80 days should not need renew")
	}

	// a cert near expiry should need renew.
	tmpl.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	der2, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	savePEMChain(filepath.Join(dir, certFile), [][]byte{der2})
	if !NeedsRenew(dir) {
		t.Fatalf("cert with 10 days left should need renew")
	}

	// missing dir -> needs renew
	if !NeedsRenew(filepath.Join(dir, "nope")) {
		t.Fatalf("missing cert should need renew")
	}
	_ = pem.Block{}
	_ = os.Stdout
}
