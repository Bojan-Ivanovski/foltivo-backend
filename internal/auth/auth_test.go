package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
)

func TestValidation(t *testing.T) {
	if got, err := Email("  Alice@EXAMPLE.com  "); err != nil || got != "alice@example.com" {
		t.Fatal("email canonicalization failed")
	}
	for _, email := range []string{"", "Display <a@example.com>", "a\n@example.com", "a@b", strings.Repeat("a", 255) + "@example.com"} {
		if _, err := Email(email); err == nil {
			t.Errorf("accepted email %q", email)
		}
	}
	if got, err := Name("  Ивана  "); err != nil || got != "Ивана" {
		t.Fatal("display name validation failed")
	}
	for _, name := range []string{"  ", "a\nb", strings.Repeat("a", 101)} {
		if _, err := Name(name); err == nil {
			t.Error("invalid name accepted")
		}
	}
	for _, password := range []string{strings.Repeat("ø", 15), strings.Repeat("a", 128), "  password with spaces  "} {
		if err := Password(password); err != nil {
			t.Fatal(err)
		}
	}
	for _, password := range []string{strings.Repeat("a", 14), strings.Repeat("ø", 129), "\xff"} {
		if err := Password(password); err == nil {
			t.Error("invalid password accepted")
		}
	}
}

func TestPasswordHasherAndAdmission(t *testing.T) {
	p, err := NewPasswords()
	if err != nil {
		t.Fatal(err)
	}
	password := "  a long unicode пароль  "
	hash, err := p.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hash, "m=65536,t=3,p=4") {
		t.Fatal("unexpected production hashing profile")
	}
	if ok, err := p.Compare(context.Background(), password, hash); err != nil || !ok {
		t.Fatal("hash comparison failed")
	}
	if ok, err := p.Compare(context.Background(), strings.TrimSpace(password), hash); err != nil || ok {
		t.Fatal("password was silently trimmed")
	}
	p.slots <- struct{}{}
	p.slots <- struct{}{}
	if _, err := p.Compare(context.Background(), password, hash); err == nil {
		t.Fatal("unbounded hashing admission")
	}
	<-p.slots
	<-p.slots
	if _, err := p.Compare(context.Background(), password, "malformed secret hash"); err != Unavailable {
		t.Fatal("unsafe hashing error")
	}
}

func TestSessionAssuranceAndTokens(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if !validToken(a) || a == b || len(tokenHash(a)) != 32 || CSRF(a) == CSRF(b) || CSRF(a) == a {
		t.Fatal("invalid opaque tokens")
	}
	s := &Session{Token: a}
	s.derive()
	if s.State != "anonymous" {
		t.Fatal(s.State)
	}
	s.User = &User{}
	s.derive()
	if s.State != "verification_required" {
		t.Fatal(s.State)
	}
	s.User.EmailVerified = true
	s.TOTPEnabled = true
	s.derive()
	if s.State != "mfa_required" {
		t.Fatal(s.State)
	}
	s.MFA = true
	s.derive()
	if s.State != "authenticated" {
		t.Fatal(s.State)
	}
	if err := s.RequireRecent(time.Now()); err == nil {
		t.Fatal("missing recent auth accepted")
	}
	now := time.Now()
	s.RecentAuthAt = &now
	if err := s.RequireRecent(now); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecent(now.Add(6 * time.Minute)); err == nil {
		t.Fatal("stale recent auth accepted")
	}
}

func fastPasswords(t *testing.T) *Passwords {
	t.Helper()
	p, err := newPasswords(&argon2id.Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
