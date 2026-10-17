package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
)

func TestDecodeStrictObject(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{}`, `{"name":null}`, `{"name":"a","name":"b"}`, `{"unexpected":"field"}`, `{"name":"a"} {}`, strings.Repeat("a", 16385)} {
		t.Run(body[:min(len(body), 40)], func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			var dto struct {
				Name string `json:"name"`
			}
			err := decode(httptest.NewRecorder(), r, &dto)
			if body == `{}` {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}

func TestOriginRejectsBeforeDatabase(t *testing.T) {
	h := New(nil, "https://foltivo.com", true).Routes()
	for _, origin := range []string{"", "null", "https://evil.foltivo.com", "https://foltivo.com.evil.com", "https://foltivo.com/"} {
		r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{}`))
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "origin_rejected") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unsafe origin accepted")
		}
	}
}

func TestCookieAndSafeError(t *testing.T) {
	h := New(nil, "https://foltivo.com", true)
	s := &auth.Session{Token: "placeholder"}
	w := httptest.NewRecorder()
	h.cookie(w, s)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-foltivo_session" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Domain != "" || cookies[0].Path != "/" {
		t.Fatal("unsafe production cookie")
	}
	w = httptest.NewRecorder()
	fail(w, &auth.Error{Status: 429, Code: "rate_limited", Message: "Try later.", RetryAfter: 30})
	if w.Code != 429 || w.Header().Get("Retry-After") != "30" {
		t.Fatal("missing retry metadata")
	}
	var value map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil || value["error"] == nil {
		t.Fatal("error contract mismatch")
	}
}

func TestPeerIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.2:9999"
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	r.Header.Set("Forwarded", "for=8.8.8.8")
	if peer(r) != "127.0.0.2" {
		t.Fatal("untrusted proxy header was trusted")
	}
}
