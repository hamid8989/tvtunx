package acmedns

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// waitTXT polls a public DoH resolver until the TXT record `fqdn` contains
// `value`, for up to ~2 minutes. Best-effort: on any error or timeout it just
// returns, and the CA's own validation (WaitAuthorization) is the real gate.
func waitTXT(fqdn, value string, logf Logf) {
	deadline := time.Now().Add(2 * time.Minute)
	cl := &http.Client{Timeout: 8 * time.Second}
	for time.Now().Before(deadline) {
		if txtHas(cl, "https://1.1.1.1/dns-query", fqdn, value) ||
			txtHas(cl, "https://dns.google/resolve", fqdn, value) {
			logf("TXT record is visible; asking the CA to validate")
			return
		}
		time.Sleep(5 * time.Second)
	}
	logf("TXT not confirmed via public DNS yet; trying the CA anyway")
}

func txtHas(cl *http.Client, doh, name, value string) bool {
	req, err := http.NewRequest(http.MethodGet, doh+"?name="+name+"&type=TXT", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := cl.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var dr struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&dr); err != nil {
		return false
	}
	for _, a := range dr.Answer {
		if a.Type == 16 && strings.Contains(a.Data, value) { // 16 = TXT
			return true
		}
	}
	return false
}
