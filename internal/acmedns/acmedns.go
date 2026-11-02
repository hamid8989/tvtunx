// Package acmedns obtains a real Let's Encrypt certificate using the ACME
// **DNS-01** challenge — validation via a DNS TXT record, needing NO open port.
// This is what lets the "browser" transport get a real cert on a server whose
// :80 and :443 are already taken (e.g. a PasarGuard/Marzban node's xray), without
// touching those services. It issues a WILDCARD cert for *.<label>.<domain>, so a
// single cert covers every PSK-rotating subdomain (no per-name issuance, no rate
// limits). The TXT record is placed either automatically (Cloudflare API) or by
// the user (manual), selected by the Provider.
package acmedns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	acctKeyFile = "acme_account.key"
	certFile    = "browser.crt"
	keyFile     = "browser.key"
)

// Provider places (and removes) the DNS-01 TXT record for a challenge.
type Provider interface {
	// Present creates a TXT record `fqdn` (e.g. _acme-challenge.t.example.com)
	// with the given value.
	Present(fqdn, value string) error
	// CleanUp removes it (best effort).
	CleanUp(fqdn, value string) error
}

// Logf is an optional progress logger.
type Logf func(format string, a ...any)

// WildcardName returns the wildcard hostname a cert is obtained for.
func WildcardName(domain, label string) string { return "*." + label + "." + domain }

// ObtainWildcard runs the DNS-01 flow for *.<label>.<domain> and saves the cert
// and key into cacheDir. staging uses Let's Encrypt's staging CA (for testing).
func ObtainWildcard(ctx context.Context, domain, label, cacheDir string, prov Provider, staging bool, logf Logf) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return err
	}
	acctKey, err := loadOrCreateKey(filepath.Join(cacheDir, acctKeyFile))
	if err != nil {
		return err
	}
	dir := acme.LetsEncryptURL
	if staging {
		dir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	cli := &acme.Client{Key: acctKey, DirectoryURL: dir}

	logf("registering ACME account")
	if _, err := cli.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil &&
		!errors.Is(err, acme.ErrAccountAlreadyExists) {
		// Register returns the existing account on most CAs; tolerate "exists".
		logf("account register: %v (continuing)", err)
	}

	name := WildcardName(domain, label)
	logf("requesting certificate for %s", name)
	order, err := cli.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return fmt.Errorf("authorize order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := cli.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("get authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return errors.New("acmedns: no dns-01 challenge offered")
		}
		val, err := cli.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		fqdn := "_acme-challenge." + authz.Identifier.Value // identifier is the base (no *.)

		logf("placing DNS TXT %s", fqdn)
		if err := prov.Present(fqdn, val); err != nil {
			return fmt.Errorf("set TXT record: %w", err)
		}
		// Best-effort wait for the TXT to be visible before asking the CA to check.
		waitTXT(fqdn, val, logf)

		if _, err := cli.Accept(ctx, chal); err != nil {
			prov.CleanUp(fqdn, val)
			return fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := cli.WaitAuthorization(ctx, authzURL); err != nil {
			prov.CleanUp(fqdn, val)
			return fmt.Errorf("authorization failed (is the TXT record correct and propagated?): %w", err)
		}
		prov.CleanUp(fqdn, val)
	}

	// Finalize: generate the certificate key + CSR for the wildcard name.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: name},
		DNSNames: []string{name},
	}, certKey)
	if err != nil {
		return err
	}
	logf("finalizing order")
	der, _, err := cli.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	if err := savePEMChain(filepath.Join(cacheDir, certFile), der); err != nil {
		return err
	}
	if err := saveECKey(filepath.Join(cacheDir, keyFile), certKey); err != nil {
		return err
	}
	logf("certificate saved to %s", cacheDir)
	return nil
}

// LoadCert loads the DNS-01 certificate+key previously saved in cacheDir.
func LoadCert(cacheDir string) (*tls.Certificate, error) {
	crt, err := tls.LoadX509KeyPair(filepath.Join(cacheDir, certFile), filepath.Join(cacheDir, keyFile))
	if err != nil {
		return nil, err
	}
	if len(crt.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(crt.Certificate[0]); err == nil {
			crt.Leaf = leaf
		}
	}
	return &crt, nil
}

// NeedsRenew reports whether the cert is missing or within 21 days of expiry.
func NeedsRenew(cacheDir string) bool {
	c, err := LoadCert(cacheDir)
	if err != nil || c.Leaf == nil {
		return true
	}
	return time.Until(c.Leaf.NotAfter) < 21*24*time.Hour
}

// ───────────────────────── key / PEM helpers ─────────────────────────

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := saveECKey(path, k); err != nil {
		return nil, err
	}
	return k, nil
}

func saveECKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

func savePEMChain(path string, der [][]byte) error {
	var buf []byte
	for _, b := range der {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	return os.WriteFile(path, buf, 0o644)
}
