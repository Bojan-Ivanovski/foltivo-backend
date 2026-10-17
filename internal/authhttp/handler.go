// Package authhttp maps the versioned browser contract to the auth service.
package authhttp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
)

type Handler struct {
	service    *auth.Service
	origin     string
	secure     bool
	cookieName string
}

func New(service *auth.Service, origin string, secure bool) *Handler {
	name := "foltivo_session"
	if secure {
		name = "__Host-foltivo_session"
	}
	return &Handler{service: service, origin: origin, secure: secure, cookieName: name}
}

type endpoint func(http.ResponseWriter, *http.Request, *auth.Session) error

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
		session, err := h.service.Session(r.Context(), h.token(r), peer(r), true)
		if err != nil {
			fail(w, err)
			return
		}
		// Do not let a late read response overwrite a cookie rotated by a
		// concurrent login/logout in another tab. Only bootstrap writes it.
		if session.Token != h.token(r) {
			h.cookie(w, session)
		}
		write(w, 200, session)
	})
	mux.HandleFunc("POST /api/v1/auth/register", h.wrap(h.register, true))
	mux.HandleFunc("POST /api/v1/auth/login", h.wrap(h.login, true))
	mux.HandleFunc("POST /api/v1/auth/logout", h.wrap(h.logout, true))
	mux.HandleFunc("GET /api/v1/me", h.wrap(h.me, false))
	mux.HandleFunc("PATCH /api/v1/auth/profile", h.wrap(h.profile, true))
	mux.HandleFunc("GET /api/v1/auth/sessions", h.wrap(h.sessions, false))
	mux.HandleFunc("DELETE /api/v1/auth/sessions/{id}", h.wrap(h.revoke, true))
	mux.HandleFunc("POST /api/v1/auth/reauthenticate", h.wrap(h.reauthenticate, true))
	mux.HandleFunc("POST /api/v1/auth/verification/resend", h.wrap(h.requestEmail("verification"), true))
	mux.HandleFunc("POST /api/v1/auth/verification/confirm", h.wrap(h.consumeEmail("verification"), true))
	mux.HandleFunc("POST /api/v1/auth/password/forgot", h.wrap(h.requestEmail("reset"), true))
	mux.HandleFunc("POST /api/v1/auth/password/reset", h.wrap(h.consumeEmail("reset"), true))
	mux.HandleFunc("POST /api/v1/auth/password/change", h.wrap(h.changePassword, true))
	mux.HandleFunc("POST /api/v1/auth/totp/enroll", h.wrap(h.enrollTOTP, true))
	mux.HandleFunc("POST /api/v1/auth/totp/confirm", h.wrap(h.confirmTOTP, true))
	mux.HandleFunc("POST /api/v1/auth/mfa/challenge", h.wrap(h.challenge, true))
	mux.HandleFunc("POST /api/v1/auth/totp/remove", h.wrap(h.modifyTOTP(true), true))
	mux.HandleFunc("POST /api/v1/auth/recovery-codes/regenerate", h.wrap(h.modifyTOTP(false), true))
	mux.HandleFunc("GET /api/v1/auth/security", h.wrap(h.security, false))
	mux.HandleFunc("POST /api/v1/auth/passkeys/register/begin", h.wrap(h.beginPasskey("registration"), true))
	mux.HandleFunc("POST /api/v1/auth/passkeys/register/finish", h.wrap(h.finishPasskey("registration"), true))
	mux.HandleFunc("POST /api/v1/auth/passkeys/login/begin", h.wrap(h.beginPasskey("login"), true))
	mux.HandleFunc("POST /api/v1/auth/passkeys/login/finish", h.wrap(h.finishPasskey("login"), true))
	mux.HandleFunc("DELETE /api/v1/auth/passkeys/{id}", h.wrap(h.removePasskey, true))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (h *Handler) wrap(fn endpoint, mutation bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bounded, cancel := context.WithTimeout(r.Context(), 7*time.Second)
		defer cancel()
		r = r.WithContext(bounded)
		if mutation && r.Header.Get("Origin") != h.origin {
			fail(w, &auth.Error{Status: 403, Code: "origin_rejected", Message: "Request origin is not trusted."})
			return
		}
		session, err := h.service.Session(r.Context(), h.token(r), peer(r), false)
		if err != nil {
			fail(w, err)
			return
		}
		if mutation && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRFToken)) != 1 {
			fail(w, &auth.Error{Status: 403, Code: "csrf_rejected", Message: "Reload this page and try again."})
			return
		}
		if err := fn(w, r, session); err != nil {
			fail(w, err)
		}
	}
}

func peer(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	// Ignore Forwarded and X-Forwarded-For. Reverse proxies require a separate,
	// explicit trusted-proxy design before they can supply a client address.
	return ip.String()
}

func (h *Handler) token(r *http.Request) string {
	c, err := r.Cookie(h.cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (h *Handler) cookie(w http.ResponseWriter, s *auth.Session) {
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: s.Token, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode, Expires: s.ExpiresAt, MaxAge: int(time.Until(s.ExpiresAt).Seconds())})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return auth.Validation("Send a JSON request body.")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return auth.Validation("Request body is invalid or too large.")
	}
	// Each DTO is an object. Reject null, duplicate fields, trailing values and
	// unknown fields rather than letting ambiguous JSON pick a credential value.
	check := json.NewDecoder(bytes.NewReader(body))
	first, err := check.Token()
	if err != nil || first != json.Delim('{') {
		return auth.Validation("Send a JSON object.")
	}
	seen := map[string]bool{}
	for check.More() {
		key, err := check.Token()
		if err != nil {
			return auth.Validation("Request body is invalid.")
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return auth.Validation("Request body has duplicate or invalid fields.")
		}
		seen[name] = true
		var value json.RawMessage
		if err := check.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return auth.Validation("Request body has invalid values.")
		}
	}
	if _, err := check.Token(); err != nil {
		return auth.Validation("Request body is invalid.")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return auth.Validation("Request body is invalid or too large.")
	}
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return auth.Validation("Send exactly one JSON object.")
	}
	return nil
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, err error) {
	var e *auth.Error
	if !errors.As(err, &e) {
		e = auth.Unavailable
	}
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	}
	write(w, e.Status, map[string]any{"error": map[string]string{"code": e.Code, "message": e.Message}})
}

func anonymous(s *auth.Session) error {
	if s.State != "anonymous" {
		return &auth.Error{Status: 409, Code: "session_exists", Message: "Sign out before signing in to another account."}
	}
	return nil
}
