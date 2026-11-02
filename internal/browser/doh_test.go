package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveDoH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "a1b2c3.t.example.com" || r.URL.Query().Get("type") != "A" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		if r.Header.Get("Accept") != "application/dns-json" {
			t.Errorf("missing dns-json Accept header")
		}
		w.Header().Set("Content-Type", "application/dns-json")
		io_WriteString(w, `{"Status":0,"Answer":[{"name":"a1b2c3.t.example.com","type":5,"data":"cname.x"},{"name":"a1b2c3.t.example.com","type":1,"data":"203.0.113.9"}]}`)
	}))
	defer srv.Close()

	ip, err := ResolveDoH(srv.URL+"/dns-query", "a1b2c3.t.example.com", srv.Client())
	if err != nil {
		t.Fatalf("ResolveDoH: %v", err)
	}
	if ip != "203.0.113.9" {
		t.Fatalf("got %q, want 203.0.113.9 (should skip the CNAME and return the A record)", ip)
	}
}

func io_WriteString(w http.ResponseWriter, s string) { _, _ = w.Write([]byte(s)) }
