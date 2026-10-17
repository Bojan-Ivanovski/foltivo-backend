package auth

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/testutil"
)

const testPassword = "correct horse battery staple"

func mustSession(t *testing.T, s *Service, token string) *Session {
	t.Helper()
	current, err := s.Session(context.Background(), token, "127.0.0.1", true)
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func mustLogin(t *testing.T, s *Service, email string) *Session {
	t.Helper()
	current := mustSession(t, s, "")
	next, err := s.Login(context.Background(), current, "127.0.0.1", email, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func assertStatus(t *testing.T, err error, status int) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Status != status {
		t.Fatalf("got %v, want status %d", err, status)
	}
}

func TestIntegrationAccountSessionLifecycle(t *testing.T) {
	pool := testutil.Database(t)
	s := NewService(NewStore(pool), fastPasswords(t))
	ctx := context.Background()
	for _, email := range []string{"Alice@EXAMPLE.com", "alice@example.com"} {
		if err := s.Register(ctx, "127.0.0.1", "Alice", email, testPassword); err != nil {
			t.Fatal(err)
		}
	}
	var users, libraries int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM libraries)").Scan(&users, &libraries); err != nil || users != 1 || libraries != 1 {
		t.Fatalf("idempotent registration users%d libraries%d", users, libraries)
	}
	anonymous := mustSession(t, s, "")
	if anonymous.User != nil || anonymous.State != "anonymous" {
		t.Fatal("registration granted identity")
	}
	pending, err := s.Login(ctx, anonymous, "127.0.0.1", "alice@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Token == anonymous.Token || pending.State != "verification_required" || pending.RecentAuthAt != nil {
		t.Fatal("login did not rotate into partial state")
	}
	_, err = s.Session(ctx, anonymous.Token, "127.0.0.1", false)
	assertStatus(t, err, 401)
	assertStatus(t, pending.RequireAuthenticated(), 403)
	_, err = s.Profile(ctx, pending, "new name")
	assertStatus(t, err, 403)
	var tokenStored []byte
	if err := pool.QueryRow(ctx, "SELECT token_hash FROM auth_sessions WHERE id=$1", pending.ID).Scan(&tokenStored); err != nil || len(tokenStored) != 32 || string(tokenStored) == pending.Token {
		t.Fatal("raw bearer was stored")
	}
	// Only this private fixture changes verification. Core has no activation API.
	if _, err := pool.Exec(ctx, "UPDATE users SET email_verified=true WHERE email='alice@example.com'"); err != nil {
		t.Fatal(err)
	}
	current := mustSession(t, s, pending.Token)
	if current.State != "authenticated" || current.User.LibraryID == "" {
		t.Fatal("verified state not derived")
	}
	restarted := NewService(NewStore(pool), fastPasswords(t))
	if after := mustSession(t, restarted, current.Token); after.ID != current.ID {
		t.Fatal("session did not survive service restart")
	}
	if err := s.Reauthenticate(ctx, current, "127.0.0.1", testPassword, ""); err != nil {
		t.Fatal(err)
	}
	current = mustSession(t, s, current.Token)
	if current.RecentAuthAt == nil {
		t.Fatal("recent assurance not persisted")
	}
	user, err := s.Profile(ctx, current, "  Updated name  ")
	if err != nil || user.Name != "Updated name" {
		t.Fatal("profile update failed")
	}
	other := mustLogin(t, s, "alice@example.com")
	items, err := s.Sessions(ctx, current)
	if err != nil || len(items) != 2 {
		t.Fatal("session inventory failed")
	}
	if err := s.Revoke(ctx, current, other.ID); err != nil {
		t.Fatal(err)
	}
	_, err = s.Session(ctx, other.Token, "127.0.0.1", false)
	assertStatus(t, err, 401)
	next, err := s.Logout(ctx, current)
	if err != nil || next.State != "anonymous" || next.Token == current.Token {
		t.Fatal("logout did not revoke/rotate")
	}
	_, err = s.Session(ctx, current.Token, "127.0.0.1", false)
	assertStatus(t, err, 401)
	_, err = s.Profile(ctx, current, "stale profile")
	assertStatus(t, err, 409)
	if err := s.Revoke(ctx, current, next.ID); err == nil {
		t.Fatal("revoked caller mutated session")
	}
}

func TestIntegrationOwnershipExpiryAndPolicy(t *testing.T) {
	pool := testutil.Database(t)
	s := NewService(NewStore(pool), fastPasswords(t))
	ctx := context.Background()
	for _, email := range []string{"alice@example.com", "bob@example.com"} {
		if err := s.Register(ctx, email, "Person", email, testPassword); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = pool.Exec(ctx, "UPDATE users SET email_verified=true")
	alice := mustLogin(t, s, "alice@example.com")
	bob := mustLogin(t, s, "bob@example.com")
	if alice.User.LibraryID == bob.User.LibraryID {
		t.Fatal("users share personal library")
	}
	assertStatus(t, s.Revoke(ctx, alice, bob.ID), 404)
	if current := mustSession(t, s, bob.Token); current.ID != bob.ID {
		t.Fatal("cross-owner deletion succeeded")
	}
	_, _ = pool.Exec(ctx, "UPDATE users SET totp_enabled=true WHERE id=$1", alice.User.ID)
	pending := mustSession(t, s, alice.Token)
	if pending.State != "mfa_required" {
		t.Fatal("factor policy not checked dynamically")
	}
	_, err := s.Profile(ctx, alice, "stale assurance")
	assertStatus(t, err, 409)
	assertStatus(t, s.Revoke(ctx, alice, alice.ID), 404)
	var revoked bool
	if err := pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id=$1", alice.ID).Scan(&revoked); err != nil || revoked {
		t.Fatal("stale policy caller revoked an owned session")
	}
	assertStatus(t, s.Revoke(ctx, alice, bob.ID), 404)
	assertStatus(t, s.Reauthenticate(ctx, pending, "127.0.0.1", testPassword, "123456"), 403)
	_, _ = pool.Exec(ctx, "UPDATE users SET security_version=security_version+1 WHERE id=$1", bob.User.ID)
	_, err = s.Session(ctx, bob.Token, "127.0.0.1", false)
	assertStatus(t, err, 401)
	if err := s.Revoke(ctx, bob, alice.ID); err == nil {
		t.Fatal("stale policy version mutated sessions")
	}
	_, _ = pool.Exec(ctx, "UPDATE auth_sessions SET expires_at=now()-interval '1 second' WHERE id=$1", alice.ID)
	_, err = s.Session(ctx, alice.Token, "127.0.0.1", false)
	assertStatus(t, err, 401)
	if fresh := mustSession(t, s, alice.Token); fresh.State != "anonymous" || fresh.Token == alice.Token {
		t.Fatal("expired bearer accepted")
	}
}

func TestIntegrationThrottleAndConcurrentRotation(t *testing.T) {
	pool := testutil.Database(t)
	s := NewService(NewStore(pool), fastPasswords(t))
	ctx := context.Background()
	if err := s.Register(ctx, "registration", "Person", "alice@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	current := mustSession(t, s, "")
	for i := 0; i < 10; i++ {
		_, err := s.Login(ctx, current, "unknown-peer", "unknown@example.com", testPassword)
		assertStatus(t, err, 401)
	}
	restarted := NewService(NewStore(pool), fastPasswords(t))
	_, err := restarted.Login(ctx, current, "other-peer", "unknown@example.com", testPassword)
	assertStatus(t, err, 429)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Login(ctx, current, "127.0.0.1", "alice@example.com", testPassword)
			if err == nil {
				statuses <- 200
				return
			}
			var e *Error
			if errors.As(err, &e) {
				statuses <- e.Status
			} else {
				statuses <- 0
			}
		}()
	}
	wg.Wait()
	close(statuses)
	seen := map[int]int{}
	for status := range statuses {
		seen[status]++
	}
	if seen[200] != 1 || seen[409] != 1 {
		t.Fatalf("concurrent rotation results%v", seen)
	}
}
