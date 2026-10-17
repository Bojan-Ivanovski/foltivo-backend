package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/Bojan-Ivanovski/foltivo-backend/internal/testutil"
	"strings"
	"testing"
)

type captureMail struct {
	bodies []string
	fail   bool
}

func (m *captureMail) Send(_ context.Context, _, _, body string) error {
	if m.fail {
		return errors.New("transport offline")
	}
	m.bodies = append(m.bodies, body)
	return nil
}
func (m *captureMail) token(t *testing.T) string {
	t.Helper()
	body := m.bodies[len(m.bodies)-1]
	parts := strings.Split(body, "#token=")
	if len(parts) != 2 {
		t.Fatal("message missing link")
	}
	return strings.Fields(parts[1])[0]
}
func TestIntegrationEmailLifecycle(t *testing.T) {
	pool := testutil.Database(t)
	s := NewService(NewStore(pool), fastPasswords(t))
	ctx := context.Background()
	secrets, err := NewSecrets(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	mail := &captureMail{fail: true}
	s.ConfigureEmail(&EmailDelivery{Origin: "http://localhost:5173", Secrets: secrets, Sender: mail})
	if err = s.Register(ctx, "registration", "Alice", "alice@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	found, err := s.DeliverEmail(ctx)
	if !found || err == nil {
		t.Fatal("failed send was not retried")
	}
	var pending int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM auth_email_outbox WHERE completed_at IS NULL").Scan(&pending)
	if pending != 1 {
		t.Fatal("delivery failure lost queued request")
	}
	mail.fail = false
	_, _ = pool.Exec(ctx, "UPDATE auth_email_outbox SET next_attempt_at=now()")
	if _, err = s.DeliverEmail(ctx); err != nil || len(mail.bodies) != 1 {
		t.Fatal("queued verification did not deliver")
	}
	token := mail.token(t)
	pendingLogin := mustLogin(t, s, "alice@example.com")
	if pendingLogin.State != "verification_required" {
		t.Fatal("unverified login granted access")
	}
	var data []byte
	_ = pool.QueryRow(ctx, "SELECT token_hash FROM auth_email_tokens LIMIT 1").Scan(&data)
	if string(data) == token {
		t.Fatal("raw token stored")
	}
	if err = s.ConsumeEmail(ctx, token, "reset", testPassword); err == nil {
		t.Fatal("verification token accepted for reset")
	}
	if err = s.ConsumeEmail(ctx, token, "verification", ""); err != nil {
		t.Fatal(err)
	}
	_, err = s.Session(ctx, pendingLogin.Token, "peer", false)
	assertStatus(t, err, 401)
	if err = s.ConsumeEmail(ctx, token, "verification", ""); err == nil {
		t.Fatal("verification replay accepted")
	}
	current := mustLogin(t, s, "alice@example.com")
	if current.State != "authenticated" {
		t.Fatal("verified login failed")
	}
	// Password recovery must not remove enrolled factors, even before #6 arrives.
	_, _ = pool.Exec(ctx, "UPDATE users SET totp_enabled=true WHERE id=$1", current.User.ID)
	if err = s.RequestEmail(ctx, "forgot", "alice@example.com", "reset"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeliverEmail(ctx); err != nil {
		t.Fatal(err)
	}
	reset := mail.token(t)
	newPassword := "a completely new password"
	if err = s.ConsumeEmail(ctx, reset, "reset", newPassword); err != nil {
		t.Fatal(err)
	}
	if err = s.ConsumeEmail(ctx, reset, "reset", newPassword); err == nil {
		t.Fatal("reset replay accepted")
	}
	_, err = s.Session(ctx, current.Token, "peer", false)
	assertStatus(t, err, 401)
	fresh := mustSession(t, s, "")
	next, err := s.Login(ctx, fresh, "peer", "alice@example.com", newPassword)
	if err != nil || next.State != "mfa_required" {
		t.Fatal("reset bypassed MFA")
	}
	if err = s.RequestEmail(ctx, "unknown", "unknown@example.com", "reset"); err != nil {
		t.Fatal("unknown account enumerated")
	}
	if found, err := s.DeliverEmail(ctx); err != nil || found {
		t.Fatal("unknown account produced mail")
	}
}

func TestSecretsIntegrityAndPurpose(t *testing.T) {
	s, err := NewSecrets(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := s.Seal([]byte("sensitive payload"), "one")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.Open(encrypted, "one")
	if err != nil || string(plain) != "sensitive payload" {
		t.Fatal("roundtrip failed")
	}
	if _, err = s.Open(encrypted, "two"); err == nil {
		t.Fatal("wrong purpose accepted")
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, err = s.Open(encrypted, "one"); err == nil {
		t.Fatal("tampered secret accepted")
	}
	if _, err = NewSecrets("placeholder"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestIntegrationPasswordChangeAndExpiredLinks(t *testing.T) {
	pool := testutil.Database(t)
	s := NewService(NewStore(pool), fastPasswords(t))
	ctx := context.Background()
	secret, _ := NewSecrets(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	mail := &captureMail{}
	s.ConfigureEmail(&EmailDelivery{Origin: "http://localhost:5173", Secrets: secret, Sender: mail})
	if err := s.Register(ctx, "peer", "Alice", "alice@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	_, _ = s.DeliverEmail(ctx)
	token := mail.token(t)
	_, _ = pool.Exec(ctx, "UPDATE auth_email_tokens SET expires_at=now()-interval '1 second'")
	if err := s.ConsumeEmail(ctx, token, "verification", ""); err == nil {
		t.Fatal("expired link accepted")
	}
	_, _ = pool.Exec(ctx, "UPDATE users SET email_verified=true")
	current := mustLogin(t, s, "alice@example.com")
	if err := s.ChangePassword(ctx, current, "peer", "a wrong password value", "a replacement password", ""); err == nil {
		t.Fatal("wrong current password accepted")
	}
	if err := s.ChangePassword(ctx, current, "peer", testPassword, "a replacement password", ""); err != nil {
		t.Fatal(err)
	}
	_, err := s.Session(ctx, current.Token, "peer", false)
	assertStatus(t, err, 401)
	anonymous := mustSession(t, s, "")
	if _, err = s.Login(ctx, anonymous, "peer", "alice@example.com", testPassword); err == nil {
		t.Fatal("old password accepted")
	}
	if next, err := s.Login(ctx, anonymous, "peer", "alice@example.com", "a replacement password"); err != nil || next.State != "authenticated" {
		t.Fatal("new password rejected")
	}
}
