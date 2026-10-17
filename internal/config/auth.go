package config

import (
	"errors"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

type Auth struct {
	Origin         string
	SecureCookies  bool
	TrustedProxies []netip.Prefix
}

// LoadAuth validates the browser-facing deployment independently of the migration
// CLI, which does not serve cookies or require an application origin.
func LoadAuth(c Config) (Auth, error) {
	origin := os.Getenv("APP_ORIGIN")
	if origin == "" && c.Environment != "production" {
		origin = "http://localhost:5173"
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "http" && u.Scheme != "https") || u.String() != origin {
		return Auth{}, errors.New("APP_ORIGIN must be an exact http(s) origin without path, credentials, query or fragment")
	}
	var proxies []netip.Prefix
	if raw := os.Getenv("TRUSTED_PROXY_CIDRS"); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			prefix, e := netip.ParsePrefix(strings.TrimSpace(value))
			if e != nil || prefix.Bits() == 0 {
				return Auth{}, errors.New("TRUSTED_PROXY_CIDRS must contain explicit non-global proxy CIDRs")
			}
			proxies = append(proxies, prefix.Masked())
		}
	}
	secure := u.Scheme == "https"
	if c.Environment == "production" {
		if !secure || os.Getenv("TRUSTED_TLS_TERMINATION") != "true" {
			return Auth{}, errors.New("production requires HTTPS APP_ORIGIN and TRUSTED_TLS_TERMINATION=true behind a trusted HTTPS reverse proxy")
		}
		if len(proxies) == 0 {
			return Auth{}, errors.New("production requires TRUSTED_PROXY_CIDRS for the actual TLS reverse proxies")
		}
		db, err := url.Parse(c.DatabaseURL)
		if err != nil || (db.Scheme != "postgres" && db.Scheme != "postgresql") || db.Query().Get("sslmode") != "verify-full" || strings.Contains(db.Query().Get("sslsni"), "0") {
			return Auth{}, errors.New("production DATABASE_URL must use PostgreSQL TLS with sslmode=verify-full")
		}
	} else if !secure && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return Auth{}, errors.New("insecure development APP_ORIGIN must use localhost or a loopback address")
	}
	return Auth{Origin: origin, SecureCookies: secure, TrustedProxies: proxies}, nil
}
