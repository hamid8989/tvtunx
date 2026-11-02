package acmedns

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ───────────────────────── manual provider ─────────────────────────

// ManualProvider prints the TXT record the user must add and waits for them to
// press Enter. For use at install time (interactive); renewal re-runs `tvtunx cert`.
type ManualProvider struct {
	In  io.Reader // defaults to os.Stdin
	Out io.Writer // defaults to os.Stdout
}

func (m *ManualProvider) Present(fqdn, value string) error {
	out := m.Out
	if out == nil {
		out = os.Stdout
	}
	in := m.In
	if in == nil {
		in = os.Stdin
	}
	fmt.Fprintf(out, "\n  Add this DNS TXT record at your domain provider:\n\n")
	fmt.Fprintf(out, "      Type:  TXT\n")
	fmt.Fprintf(out, "      Name:  %s\n", fqdn)
	fmt.Fprintf(out, "      Value: %s\n\n", value)
	fmt.Fprintf(out, "  Press Enter once you've added it (give DNS a minute to update)... ")
	bufio.NewReader(in).ReadString('\n')
	return nil
}

func (m *ManualProvider) CleanUp(fqdn, value string) error {
	out := m.Out
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, "  (You can remove the TXT record %s now.)\n", fqdn)
	return nil
}

// ───────────────────────── Cloudflare provider ─────────────────────────

// CloudflareProvider creates/deletes the TXT record via the Cloudflare API using
// a scoped API token (Zone:DNS:Edit). Zone is the registrable domain (the zone
// name in Cloudflare), e.g. example.com.
type CloudflareProvider struct {
	Token   string
	Zone    string
	APIBase string // default https://api.cloudflare.com/client/v4
	Client  *http.Client

	zoneID  string
	records map[string]string // fqdn|value -> record id (for cleanup)
}

func (c *CloudflareProvider) base() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return "https://api.cloudflare.com/client/v4"
}

func (c *CloudflareProvider) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

type cfResp struct {
	Success bool              `json:"success"`
	Errors  []json.RawMessage `json:"errors"`
	Result  json.RawMessage   `json:"result"`
}

func (c *CloudflareProvider) do(method, url string, body any) (json.RawMessage, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var cr cfResp
	if err := json.Unmarshal(raw, &cr); err != nil {
		return nil, fmt.Errorf("cloudflare: bad response (%s): %s", resp.Status, string(raw))
	}
	if !cr.Success {
		return nil, fmt.Errorf("cloudflare API error (%s): %s", resp.Status, string(raw))
	}
	return cr.Result, nil
}

func (c *CloudflareProvider) resolveZoneID() error {
	if c.zoneID != "" {
		return nil
	}
	res, err := c.do(http.MethodGet, c.base()+"/zones?name="+c.Zone, nil)
	if err != nil {
		return err
	}
	var zones []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res, &zones); err != nil {
		return err
	}
	if len(zones) == 0 {
		return errors.New("cloudflare: zone not found: " + c.Zone)
	}
	c.zoneID = zones[0].ID
	return nil
}

func (c *CloudflareProvider) Present(fqdn, value string) error {
	if err := c.resolveZoneID(); err != nil {
		return err
	}
	res, err := c.do(http.MethodPost, c.base()+"/zones/"+c.zoneID+"/dns_records", map[string]any{
		"type":    "TXT",
		"name":    fqdn,
		"content": value,
		"ttl":     60,
	})
	if err != nil {
		return err
	}
	var rec struct {
		ID string `json:"id"`
	}
	json.Unmarshal(res, &rec)
	if c.records == nil {
		c.records = map[string]string{}
	}
	c.records[fqdn+"|"+value] = rec.ID
	return nil
}

func (c *CloudflareProvider) CleanUp(fqdn, value string) error {
	id := c.records[fqdn+"|"+value]
	if id == "" || c.zoneID == "" {
		return nil
	}
	_, err := c.do(http.MethodDelete, c.base()+"/zones/"+c.zoneID+"/dns_records/"+id, nil)
	delete(c.records, fqdn+"|"+value)
	return err
}
