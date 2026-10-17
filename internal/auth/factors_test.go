package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/testutil"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

func factorCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(secret, uint64(step), hotp.ValidateOpts{
		Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal("could not create a test authenticator code")
	}
	return code
}

func assertFactorError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var got *Error
	if !errors.As(err, &got) || got.Status != status || got.Code != code {
		t.Fatalf("got error %v, want %s with status %d", err, code, status)
	}
}

func TestIntegrationTOTPLifecycle(t *testing.T) {
	pool := testutil.Database(t)
	s := NewService(NewStore(pool), fastPasswords(t))
	ctx := context.Background()
	const email = "factor@example.com"
	if err := s.Register(ctx, "127.0.0.1", "Factor Person", email, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE users SET email_verified=true WHERE email=$1", email); err != nil {
		t.Fatal("could not prepare verified integration user")
	}

	secrets, err := NewSecrets(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal("could not configure test secret encryption")
	}
	s.ConfigureEmail(&EmailDelivery{Secrets: secrets})

	current := mustLogin(t, s, email)
	preEnrollment := mustLogin(t, s, email)
	if preEnrollment.State != "authenticated" {
		t.Fatal("pending authenticator enrollment affected sign-in")
	}
	enrollment, err := s.EnrollTOTP(ctx, current)
	if err != nil {
		t.Fatal("authenticator enrollment failed")
	}
	var factorEnabled, accountEnabled bool
	if err = pool.QueryRow(ctx, `SELECT f.enabled,u.totp_enabled FROM auth_totp f JOIN users u ON u.id=f.user_id WHERE u.email=$1`, email).Scan(&factorEnabled, &accountEnabled); err != nil {
		t.Fatal("could not inspect pending authenticator")
	}
	if factorEnabled || accountEnabled {
		t.Fatal("pending authenticator became enabled before confirmation")
	}

	step := time.Now().Unix() / 30
	// Align this disposable schema's accepted-step counter immediately before
	// the code under test instead of sleeping for a wall-clock TOTP boundary.
	if _, err = pool.Exec(ctx, "UPDATE auth_totp SET last_step=$2 WHERE user_id=$1", current.User.ID, step-2); err != nil {
		t.Fatal("could not set isolated authenticator counter")
	}
	unconfirmedLogin := mustLogin(t, s, email)
	if unconfirmedLogin.State != "authenticated" {
		t.Fatal("unconfirmed authenticator enrollment affected new sign-in")
	}
	confirmCode := factorCode(t, enrollment.Secret, step-1)
	recoveryCodes, err := s.ConfirmTOTP(ctx, current, "127.0.0.1", confirmCode)
	if err != nil || len(recoveryCodes) != 10 {
		t.Fatal("authenticator confirmation or recovery-code creation failed")
	}
	for _, old := range []*Session{preEnrollment, unconfirmedLogin} {
		if _, err = s.Session(ctx, old.Token, "127.0.0.1", false); err == nil {
			t.Fatal("confirming the factor did not revoke the other session")
		}
	}
	current = mustSession(t, s, current.Token)
	if current.State != "authenticated" || !current.MFA || !current.TOTPEnabled {
		t.Fatal("confirmation did not retain the verified current session")
	}

	pending := mustLogin(t, s, email)
	if pending.State != "mfa_required" {
		t.Fatal("password sign-in bypassed the enabled authenticator")
	}
	if _, err = s.Profile(ctx, pending, "Blocked before MFA"); err == nil {
		t.Fatal("MFA-pending session accessed protected profile")
	} else {
		assertStatus(t, err, 403)
	}
	challengeCode := factorCode(t, enrollment.Secret, step)
	verified, err := s.Challenge(ctx, pending, "127.0.0.1", challengeCode, "")
	if err != nil || verified.State != "authenticated" || !verified.MFA || verified.Token == pending.Token {
		t.Fatal("authenticator challenge did not rotate into an authenticated session")
	}
	if _, err = s.Session(ctx, pending.Token, "127.0.0.1", false); err == nil {
		t.Fatal("MFA challenge left the pending session active")
	}

	totpReplay := mustLogin(t, s, email)
	_, err = s.Challenge(ctx, totpReplay, "127.0.0.1", challengeCode, "")
	assertFactorError(t, err, 401, "invalid_factor")

	otherPending := mustLogin(t, s, email)
	recoveryPending := mustLogin(t, s, email)
	if otherPending.State != "mfa_required" || recoveryPending.State != "mfa_required" {
		t.Fatal("second-factor policy was not applied to new sessions")
	}
	recovered, err := s.Challenge(ctx, recoveryPending, "127.0.0.1", "", recoveryCodes[0])
	if err != nil || recovered.State != "authenticated" || recovered.Token == recoveryPending.Token {
		t.Fatal("recovery code did not rotate into an authenticated session")
	}
	for _, old := range []*Session{verified, otherPending, recoveryPending} {
		if _, err = s.Session(ctx, old.Token, "127.0.0.1", false); err == nil {
			t.Fatal("recovery did not revoke other sessions")
		}
	}
	replayPending := mustLogin(t, s, email)
	_, err = s.Challenge(ctx, replayPending, "127.0.0.1", "", recoveryCodes[0])
	assertFactorError(t, err, 401, "invalid_factor")

	modifyCode := factorCode(t, enrollment.Secret, step+1)
	_, err = s.ModifyTOTP(ctx, recovered, "127.0.0.1", "incorrect password", modifyCode, false)
	assertFactorError(t, err, 401, "invalid_credentials")
	_, err = s.ModifyTOTP(ctx, recovered, "127.0.0.1", testPassword, confirmCode, false)
	assertFactorError(t, err, 401, "invalid_factor")
	newRecoveryCodes, err := s.ModifyTOTP(ctx, recovered, "127.0.0.1", testPassword, modifyCode, false)
	if err != nil || len(newRecoveryCodes) != 10 || newRecoveryCodes[0] == recoveryCodes[0] {
		t.Fatal("fresh password and authenticator code did not regenerate recovery codes")
	}

	// A separate account has an independent TOTP counter so Reauthenticate can
	// validate both its missing-factor denial and a fresh successful code.
	const secondEmail = "reauth-factor@example.com"
	if err = s.Register(ctx, "127.0.0.1", "Reauth Person", secondEmail, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET email_verified=true WHERE email=$1", secondEmail); err != nil {
		t.Fatal("could not prepare second verified integration user")
	}
	second := mustLogin(t, s, secondEmail)
	secondEnrollment, err := s.EnrollTOTP(ctx, second)
	if err != nil {
		t.Fatal("second authenticator enrollment failed")
	}
	if _, err = s.ConfirmTOTP(ctx, second, "127.0.0.1", factorCode(t, secondEnrollment.Secret, step-1)); err != nil {
		t.Fatal("second authenticator confirmation failed")
	}
	second = mustSession(t, s, second.Token)
	err = s.Reauthenticate(ctx, second, "127.0.0.1", testPassword, "")
	assertFactorError(t, err, 401, "invalid_factor")
	if err = s.Reauthenticate(ctx, second, "127.0.0.1", testPassword, factorCode(t, secondEnrollment.Secret, step)); err != nil {
		t.Fatal("fresh authenticator code did not satisfy reauthentication")
	}
	second = mustSession(t, s, second.Token)
	if second.RecentAuthAt == nil || time.Since(*second.RecentAuthAt) > time.Minute {
		t.Fatal("successful factor reauthentication did not refresh assurance")
	}
}

func TestIntegrationTOTPExpiryAndRemoval(t *testing.T) {
	pool := testutil.Database(t)
	ctx := context.Background()
	s := NewService(NewStore(pool), fastPasswords(t))
	if err := s.Register(ctx, "peer", "Expiry Person", "expiry@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	_, _ = pool.Exec(ctx, "UPDATE users SET email_verified=true")
	secrets, _ := NewSecrets(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	s.ConfigureEmail(&EmailDelivery{Secrets: secrets})
	current := mustLogin(t, s, "expiry@example.com")
	enrollment, err := s.EnrollTOTP(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err = pool.QueryRow(ctx, "SELECT secret FROM auth_totp WHERE user_id=$1", current.User.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if string(encrypted) == enrollment.Secret {
		t.Fatal("plaintext TOTP secret stored")
	}
	_, _ = pool.Exec(ctx, "UPDATE auth_totp SET pending_expires_at=now()-interval '1 second'")
	if _, err = s.ConfirmTOTP(ctx, current, "peer", factorCode(t, enrollment.Secret, time.Now().Unix()/30)); err == nil {
		t.Fatal("expired enrollment accepted")
	}
	enrollment, err = s.EnrollTOTP(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	step := time.Now().Unix() / 30
	if _, err = s.ConfirmTOTP(ctx, current, "peer", factorCode(t, enrollment.Secret, step-1)); err != nil {
		t.Fatal(err)
	}
	// The pre-activation snapshot must not authorize another sensitive write.
	if _, err = s.ModifyTOTP(ctx, current, "peer", testPassword, factorCode(t, enrollment.Secret, step), true); err == nil {
		t.Fatal("stale session snapshot allowed factor removal")
	}
	current = mustSession(t, s, current.Token)
	if _, err = s.ModifyTOTP(ctx, current, "peer", testPassword, factorCode(t, enrollment.Secret, step), true); err != nil {
		t.Fatal(err)
	}
	current = mustSession(t, s, current.Token)
	security, err := s.Security(ctx, current)
	if err != nil || security.TOTPEnabled || security.RecoveryCodesRemaining != 0 {
		t.Fatal("factor removal left enabled state or backup codes")
	}
	if next := mustLogin(t, s, "expiry@example.com"); next.State != "authenticated" {
		t.Fatal("removed factor still required")
	}
}

func TestIntegrationLostAuthenticatorRecoveryManagement(t *testing.T) {
	pool := testutil.Database(t)
	ctx := context.Background()
	s := NewService(NewStore(pool), fastPasswords(t))
	if err := s.Register(ctx, "peer", "Recovery Person", "lost@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	_, _ = pool.Exec(ctx, "UPDATE users SET email_verified=true")
	secrets, _ := NewSecrets(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	s.ConfigureEmail(&EmailDelivery{Secrets: secrets})
	current := mustLogin(t, s, "lost@example.com")
	enrollment, err := s.EnrollTOTP(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.ConfirmTOTP(ctx, current, "peer", factorCode(t, enrollment.Secret, time.Now().Unix()/30))
	if err != nil {
		t.Fatal(err)
	}
	current = mustSession(t, s, current.Token)
	other := mustLogin(t, s, "lost@example.com")
	if err = s.Reauthenticate(ctx, current, "peer", testPassword, codes[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, other.Token, "peer", false); err == nil {
		t.Fatal("recovery reauthentication left another session active")
	}
	current = mustSession(t, s, current.Token)
	if err = s.Reauthenticate(ctx, current, "peer", testPassword, codes[0]); err == nil {
		t.Fatal("recovery reauthentication accepted replay")
	}
	newPassword := "a recovered replacement password"
	if err = s.ChangePassword(ctx, current, "peer", testPassword, newPassword, codes[1]); err != nil {
		t.Fatal("recovery proof failed password change", err)
	}
	if _, err = s.Session(ctx, current.Token, "peer", false); err == nil {
		t.Fatal("password change retained current session")
	}
	pending, err := s.Login(ctx, mustSession(t, s, ""), "peer", "lost@example.com", newPassword)
	if err != nil || pending.State != "mfa_required" {
		t.Fatal("password change bypassed factor")
	}
	current, err = s.Challenge(ctx, pending, "peer", "", codes[2])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ModifyTOTP(ctx, current, "peer", "wrong password value", codes[3], true); err == nil {
		t.Fatal("recovery management bypassed password")
	}
	if _, err = s.ModifyTOTP(ctx, current, "peer", newPassword, codes[3], true); err != nil {
		t.Fatal(err)
	}
	current = mustSession(t, s, current.Token)
	security, err := s.Security(ctx, current)
	if err != nil || security.TOTPEnabled || security.RecoveryCodesRemaining != 0 {
		t.Fatal("lost factor recovery left enabled factor or backup codes")
	}
}
