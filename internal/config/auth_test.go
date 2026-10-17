package config

import "testing"

func TestAuthConfiguration(t *testing.T) {
	t.Setenv("APP_ORIGIN", "")
	t.Setenv("TRUSTED_TLS_TERMINATION", "")
	c := Config{Environment: "development"}
	if got, err := LoadAuth(c); err != nil || got.Origin != "http://localhost:5173" || got.SecureCookies {
		t.Fatal("invalid local defaults")
	}
	for _, origin := range []string{"https://user:pass@example.com", "https://example.com/", "https://example.com?x=1", "http://untrusted.example.com", "null"} {
		t.Setenv("APP_ORIGIN", origin)
		if _, err := LoadAuth(c); err == nil {
			t.Errorf("accepted origin%q", origin)
		}
	}
	c.Environment = "production"
	c.DatabaseURL = "postgres://placeholder@database/db?sslmode=disable"
	t.Setenv("APP_ORIGIN", "https://foltivo.com")
	if _, err := LoadAuth(c); err == nil {
		t.Fatal("production without trusted TLS termination accepted")
	}
	t.Setenv("TRUSTED_TLS_TERMINATION", "true")
	if _, err := LoadAuth(c); err == nil {
		t.Fatal("production without database TLS accepted")
	}
	c.DatabaseURL = "postgres://placeholder@database/db?sslmode=verify-full"
	if got, err := LoadAuth(c); err != nil || !got.SecureCookies {
		t.Fatal("valid production configuration rejected")
	}
}
