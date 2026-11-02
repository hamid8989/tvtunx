package browser

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DoH (DNS over HTTPS) lets the relay resolve the exit's (rotating) hostname
// through an encrypted lookup to a big public resolver, so the censor never sees
// the hostname in a plaintext DNS query — it sees only ordinary DoH traffic to
// Cloudflare/Google. (The data connection's destination IP is still visible on the
// wire; DoH hides the *lookup*, not the data path. Combine with IP rotation for
// more.) This uses the JSON DoH API (RFC 8484 servers that speak application/
// dns-json, e.g. https://cloudflare-dns.com/dns-query, https://dns.google/resolve).

type dohAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}
type dohResponse struct {
	Answer []dohAnswer `json:"Answer"`
}

// ResolveDoH resolves name's A record via the DoH endpoint and returns the first
// IPv4 address. client may be nil (a default with a short timeout is used).
func ResolveDoH(dohURL, name string, client *http.Client) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("name", name)
	q.Set("type", "A")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("doh: resolver returned status " + resp.Status)
	}
	var dr dohResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&dr); err != nil {
		return "", err
	}
	for _, a := range dr.Answer {
		if a.Type == 1 { // A record
			if ip := net.ParseIP(a.Data); ip != nil && ip.To4() != nil {
				return a.Data, nil
			}
		}
	}
	return "", errors.New("doh: no A record for " + name)
}
