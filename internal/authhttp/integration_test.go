package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/testutil"
)

type browser struct {
	h      http.Handler
	cookie *http.Cookie
	csrf   string
	state  string
}

func (b *browser) request(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://localhost:5173")
	r.Header.Set("X-CSRF-Token", b.csrf)
	if b.cookie != nil {
		r.AddCookie(b.cookie)
	}
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, r)
	if cookies := w.Result().Cookies(); len(cookies) > 0 {
		b.cookie = cookies[0]
	}
	if w.Code == 200 && strings.Contains(w.Body.String(), `"csrfToken"`) {
		var session auth.Session
		if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
			panic(err)
		}
		b.csrf = session.CSRFToken
		b.state = session.State
	}
	return w
}

func TestIntegrationBrowserContract(t *testing.T) {
	pool := testutil.Database(t)
	passwords, err := auth.NewPasswords()
	if err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(auth.NewStore(pool), passwords)
	b := &browser{h: New(service, "http://localhost:5173", false).Routes()}
	if w := b.request("GET", "/api/v1/me", ""); w.Code != 401 {
		t.Fatal("anonymous /me permitted")
	}
	if w := b.request("GET", "/api/v1/auth/session", ""); w.Code != 200 || b.state != "anonymous" || b.csrf == "" {
		t.Fatal("bootstrap failed", w.Body.String())
	}
	if w := b.request("GET", "/api/v1/auth/session", ""); len(w.Result().Cookies()) != 0 {
		t.Fatal("session refresh rewrote existing cookie")
	}
	anonymousToken := b.cookie.Value
	csrf := b.csrf
	b.csrf = "wrong"
	if w := b.request("POST", "/api/v1/auth/login", `{"email":"alice@example.com","password":"correct horse battery staple"}`); w.Code != 403 {
		t.Fatal("login CSRF accepted")
	}
	b.csrf = csrf
	for _, body := range []string{`{"name":"Alice","email":"alice@example.com","password":"correct horse battery staple","emailVerified":true}`, `null`, `{"name":"a","name":"b"}`} {
		if w := b.request("POST", "/api/v1/auth/register", body); w.Code != 400 {
			t.Fatal("invalid/forged registration accepted")
		}
	}
	request := `{"name":"Alice","email":"alice@example.com","password":"correct horse battery staple"}`
	first := b.request("POST", "/api/v1/auth/register", request)
	second := b.request("POST", "/api/v1/auth/register", request)
	if first.Code != 202 || second.Code != 202 || first.Body.String() != second.Body.String() || b.cookie.Value != anonymousToken {
		t.Fatal("registration enumerated or auto-signed-in")
	}
	w := b.request("POST", "/api/v1/auth/login", `{"email":"alice@example.com","password":"correct horse battery staple"}`)
	if w.Code != 200 || b.state != "verification_required" || b.cookie.Value == anonymousToken {
		t.Fatal("partial login failed", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"totp":true`) || !strings.Contains(w.Body.String(), `"passkey":true`) {
		t.Fatal("supported authentication methods missing")
	}
	if w := b.request("GET", "/api/v1/me", ""); w.Code != 403 {
		t.Fatal("unverified account protected access")
	}
	if w := b.request("PATCH", "/api/v1/auth/profile", `{"name":"Updated"}`); w.Code != 403 {
		t.Fatal("partial account profile access")
	}
	if w := b.request("POST", "/api/v1/auth/register", request); w.Code != 409 {
		t.Fatal("pending session registered another identity")
	}
	// Verification arrives in #5; this trusted fixture supplies its eventual DB effect.
	if _, err := pool.Exec(context.Background(), "UPDATE users SET email_verified=true WHERE email='alice@example.com'"); err != nil {
		t.Fatal(err)
	}
	if w := b.request("GET", "/api/v1/auth/session", ""); w.Code != 200 || b.state != "authenticated" {
		t.Fatal("verification did not update authoritative state")
	}
	if w := b.request("GET", "/api/v1/me", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"libraryId"`) {
		t.Fatal("protected user shape failed")
	}
	if w := b.request("PATCH", "/api/v1/auth/profile", `{"name":"Updated"}`); w.Code != 200 {
		t.Fatal("profile failed")
	}
	if w := b.request("POST", "/api/v1/auth/reauthenticate", `{"password":"correct horse battery staple"}`); w.Code != 200 {
		t.Fatal("reauthentication failed", w.Body.String())
	}
	if w := b.request("GET", "/api/v1/auth/sessions", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"current":true`) {
		t.Fatal("session list failed")
	}
	oldCookie := *b.cookie
	if w := b.request("POST", "/api/v1/auth/logout", `{}`); w.Code != 200 || b.state != "anonymous" || b.cookie.Value == oldCookie.Value {
		t.Fatal("logout failed")
	}
	b.cookie = &oldCookie
	if w := b.request("GET", "/api/v1/me", ""); w.Code != 401 {
		t.Fatal("revoked bearer accepted")
	}
}
