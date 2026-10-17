package authhttp

import (
	"fmt"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/testutil"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestTrustedProxyClientAddress(t *testing.T) {
	handler := New(nil, "https://foltivo.com", true, netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.1.1.2/32"))
	for _, test := range []struct{ name, remote, forwarded, want string }{
		{"untrusted spoof", "192.0.2.1:123", "198.51.100.2", "192.0.2.1"},
		{"one trusted proxy", "127.0.0.1:123", "198.51.100.2", "198.51.100.2"},
		{"ignore spoofed leftmost", "127.0.0.1:123", "203.0.113.99,198.51.100.2", "198.51.100.2"},
		{"trusted chain", "127.0.0.1:123", "198.51.100.2,10.1.1.2", "198.51.100.2"},
		{"IPv6 client", "127.0.0.1:123", "2001:db8::7", "2001:db8::7"},
		{"malformed chain", "127.0.0.1:123", "invalid,198.51.100.2", "127.0.0.1"},
		{"missing metadata", "127.0.0.1:123", "", "127.0.0.1"},
		{"zoned address", "127.0.0.1:123", "fe80::1%eth0", "127.0.0.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = test.remote
			r.Header.Set("X-Forwarded-For", test.forwarded)
			if got := handler.peer(r); got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Add("X-Forwarded-For", "198.51.100.2")
	r.Header.Add("X-Forwarded-For", "203.0.113.4")
	if handler.peer(r) != "127.0.0.1" {
		t.Fatal("ambiguous header accepted")
	}
}

func TestIntegrationProxyLimitsSeparateClients(t *testing.T) {
	pool := testutil.Database(t)
	passwords, err := auth.NewPasswords()
	if err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(auth.NewStore(pool), passwords)
	handler := New(service, "https://foltivo.com", true, netip.MustParsePrefix("127.0.0.1/32")).Routes()
	// More than the per-address bootstrap budget can use one proxy when its
	// metadata identifies separate clients. Spoofed leftmost entries are ignored.
	for i := 1; i <= 65; i++ {
		r := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
		r.RemoteAddr = "127.0.0.1:123"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.99,198.51.100.%d", i))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("separate client %d received status %d", i, w.Code)
		}
	}
}
