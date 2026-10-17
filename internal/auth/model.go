// Package auth implements the application's identity and assurance boundary.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

type Error struct {
	Status     int
	Code       string
	Message    string
	RetryAfter int
}

func (e *Error) Error() string { return e.Message }

var (
	Unavailable        = &Error{Status: 503, Code: "unavailable", Message: "Authentication is temporarily unavailable. Try again shortly."}
	Unauthenticated    = &Error{Status: 401, Code: "unauthenticated", Message: "Sign in to continue."}
	InvalidCredentials = &Error{Status: 401, Code: "invalid_credentials", Message: "Email or password is incorrect."}
	Conflict           = &Error{Status: 409, Code: "conflict", Message: "Your session changed. Reload and try again."}
)

func Validation(message string) error {
	return &Error{Status: 400, Code: "validation_error", Message: message}
}

type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"emailVerified"`
	LibraryID     string `json:"libraryId"`
}

type Session struct {
	ID           string     `json:"-"`
	User         *User      `json:"user"`
	State        string     `json:"state"`
	CSRFToken    string     `json:"csrfToken"`
	Methods      Methods    `json:"methods"`
	CreatedAt    time.Time  `json:"-"`
	ExpiresAt    time.Time  `json:"-"`
	RecentAuthAt *time.Time `json:"-"`
	UserVersion  int64      `json:"-"`
	MFA          bool       `json:"-"`
	TOTPEnabled  bool       `json:"-"`
	Token        string     `json:"-"`
}

type Methods struct {
	Password bool `json:"password"`
	TOTP     bool `json:"totp"`
	Passkey  bool `json:"passkey"`
}

func (s *Session) derive() {
	s.Methods = Methods{Password: true, TOTP: true, Passkey: true}
	s.State = "anonymous"
	if s.User != nil {
		s.State = "authenticated"
		if !s.User.EmailVerified {
			s.State = "verification_required"
		} else if s.TOTPEnabled && !s.MFA {
			s.State = "mfa_required"
		}
	}
	s.CSRFToken = CSRF(s.Token)
}

func (s *Session) RequireAuthenticated() error {
	if s.User == nil {
		return Unauthenticated
	}
	if s.State != "authenticated" {
		return &Error{Status: 403, Code: s.State, Message: "Complete email verification and required authentication factors to continue."}
	}
	return nil
}

func (s *Session) RequireRecent(now time.Time) error {
	if err := s.RequireAuthenticated(); err != nil {
		return err
	}
	if s.RecentAuthAt == nil || now.Sub(*s.RecentAuthAt) > 5*time.Minute {
		return &Error{Status: 403, Code: "reauthentication_required", Message: "Confirm your identity again to continue."}
	}
	return nil
}

func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", Unavailable
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func tokenHash(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }

func validToken(token string) bool {
	b, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == token
}

func CSRF(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("foltivo/session/csrf/v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func safe(err error) error {
	if err == nil {
		return nil
	}
	var expected *Error
	if errors.As(err, &expected) {
		return expected
	}
	return Unavailable
}
