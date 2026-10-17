package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

var invalidFactor = &Error{Status: 401, Code: "invalid_factor", Message: "Authentication code is invalid, expired or already used."}

// factorAccount locks the identity before any session/factor rows. It checks
// live policy rather than trusting the handler's earlier session snapshot.
func (s *Service) factorAccount(ctx context.Context, tx pgx.Tx, current *Session, recent bool, partial bool) (*account, error) {
	if current.User == nil {
		return nil, Unauthenticated
	}
	a, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 FOR UPDATE OF u`, current.User.ID))
	if err != nil {
		return nil, err
	}
	if a == nil || a.Version != current.UserVersion || !a.EmailVerified {
		return nil, Conflict
	}
	var sessionID string
	err = tx.QueryRow(ctx, `SELECT id::text FROM auth_sessions WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>now() AND user_version=$3 AND ($4 OR NOT $5 OR mfa_verified) AND (NOT $6 OR recent_auth_at>now()-interval '5 minutes') FOR UPDATE`, current.ID, tokenHash(current.Token), a.Version, partial, a.TOTPEnabled, recent).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, Conflict
	}
	if err != nil {
		return nil, safe(err)
	}
	return a, nil
}

func (s *Service) factorLimit(ctx context.Context, current *Session, peer string) error {
	if current.User == nil {
		return Unauthenticated
	}
	if err := s.store.throttle(ctx, "factor/ip/"+peer, 30); err != nil {
		return err
	}
	return s.store.throttle(ctx, "factor/user/"+current.User.ID, 10)
}

type Enrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

func (s *Service) EnrollTOTP(ctx context.Context, current *Session) (*Enrollment, error) {
	if err := current.RequireRecent(time.Now()); err != nil {
		return nil, err
	}
	if s.email == nil {
		return nil, Unavailable
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Foltivo", AccountName: current.User.Email, SecretSize: 20})
	if err != nil {
		return nil, Unavailable
	}
	encrypted, err := s.email.Secrets.Seal([]byte(key.Secret()), "totp/"+current.User.ID)
	if err != nil {
		return nil, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, true, false)
	if err != nil {
		return nil, err
	}
	if a.TOTPEnabled {
		return nil, Validation("An authenticator is already enrolled.")
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_totp(user_id,secret) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret,enabled=false,pending_expires_at=now()+interval '10 minutes',last_step=-1`, a.ID, encrypted)
	if err != nil {
		return nil, safe(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, safe(err)
	}
	return &Enrollment{Secret: key.Secret(), URI: key.URL()}, nil
}

// consumeTOTP runs while the account is locked, consuming the accepted time
// step globally across sessions. A previous or already used step never works.
func (s *Service) consumeTOTP(ctx context.Context, tx pgx.Tx, id, code string, pending bool) error {
	if s.email == nil {
		return Unavailable
	}
	if len(code) != 6 {
		return invalidFactor
	}
	if _, err := strconv.Atoi(code); err != nil {
		return invalidFactor
	}
	var encrypted []byte
	var last int64
	err := tx.QueryRow(ctx, `SELECT secret,last_step FROM auth_totp WHERE user_id=$1 AND enabled=$2 AND (enabled OR pending_expires_at>now()) FOR UPDATE`, id, !pending).Scan(&encrypted, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return invalidFactor
	}
	if err != nil {
		return safe(err)
	}
	secret, err := s.email.Secrets.Open(encrypted, "totp/"+id)
	if err != nil {
		return err
	}
	step := time.Now().Unix() / 30
	accepted := int64(-1)
	for _, candidate := range []int64{step, step - 1, step + 1} {
		expected, e := hotp.GenerateCodeCustom(string(secret), uint64(candidate), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e != nil {
			return Unavailable
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && candidate > last {
			accepted = candidate
			break
		}
	}
	if accepted < 0 {
		return invalidFactor
	}
	_, err = tx.Exec(ctx, "UPDATE auth_totp SET last_step=$2 WHERE user_id=$1", id, accepted)
	return safe(err)
}

func newRecoveryCodes(ctx context.Context, tx pgx.Tx, id string) ([]string, error) {
	if _, err := tx.Exec(ctx, "DELETE FROM auth_recovery_codes WHERE user_id=$1", id); err != nil {
		return nil, safe(err)
	}
	codes := make([]string, 10)
	for i := range codes {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, Unavailable
		}
		codes[i] = base64.RawURLEncoding.EncodeToString(b)
		if _, err := tx.Exec(ctx, "INSERT INTO auth_recovery_codes(user_id,code_hash) VALUES($1,$2)", id, tokenHash(codes[i])); err != nil {
			return nil, safe(err)
		}
	}
	return codes, nil
}

// factorChange invalidates other sessions and in-flight ceremonies, retaining
// the already verified current browser so enrollment codes remain visible.
func factorChange(ctx context.Context, tx pgx.Tx, a *account, current *Session) error {
	if _, err := tx.Exec(ctx, "UPDATE users SET security_version=security_version+1,updated_at=now() WHERE id=$1", a.ID); err != nil {
		return safe(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL", a.ID, current.ID); err != nil {
		return safe(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE auth_sessions SET user_version=$2,mfa_verified=true,recent_auth_at=now() WHERE id=$1", current.ID, a.Version+1); err != nil {
		return safe(err)
	}
	_, err := tx.Exec(ctx, "DELETE FROM auth_ceremonies WHERE user_id=$1", a.ID)
	return safe(err)
}

func (s *Service) ConfirmTOTP(ctx context.Context, current *Session, peer, code string) ([]string, error) {
	if err := current.RequireRecent(time.Now()); err != nil {
		return nil, err
	}
	if err := s.factorLimit(ctx, current, peer); err != nil {
		return nil, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, true, false)
	if err != nil {
		return nil, err
	}
	if a.TOTPEnabled {
		return nil, Conflict
	}
	if err = s.consumeTOTP(ctx, tx, a.ID, code, true); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "UPDATE auth_totp SET enabled=true WHERE user_id=$1", a.ID); err != nil {
		return nil, safe(err)
	}
	if _, err = tx.Exec(ctx, "UPDATE users SET totp_enabled=true WHERE id=$1", a.ID); err != nil {
		return nil, safe(err)
	}
	codes, err := newRecoveryCodes(ctx, tx, a.ID)
	if err != nil {
		return nil, err
	}
	if err = factorChange(ctx, tx, a, current); err != nil {
		return nil, err
	}
	return codes, safe(tx.Commit(ctx))
}

func (s *Service) Challenge(ctx context.Context, current *Session, peer, code, recovery string) (*Session, error) {
	if current.State != "mfa_required" {
		return nil, Conflict
	}
	if (code == "") == (recovery == "") {
		return nil, Validation("Provide one authentication code or recovery code.")
	}
	if err := s.factorLimit(ctx, current, peer); err != nil {
		return nil, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, false, true)
	if err != nil {
		return nil, err
	}
	if !a.TOTPEnabled {
		return nil, Conflict
	}
	if recovery != "" {
		result, e := tx.Exec(ctx, "UPDATE auth_recovery_codes SET consumed_at=now() WHERE user_id=$1 AND code_hash=$2 AND consumed_at IS NULL", a.ID, tokenHash(recovery))
		if e != nil {
			return nil, safe(e)
		}
		if result.RowsAffected() != 1 {
			return nil, invalidFactor
		}
		// A recovered browser invalidates all existing sessions before minting a new one.
		if _, err = tx.Exec(ctx, "UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1", a.ID); err != nil {
			return nil, safe(err)
		}
	} else {
		if err = s.consumeTOTP(ctx, tx, a.ID, code, false); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE auth_sessions SET revoked_at=now() WHERE id=$1", current.ID); err != nil {
		return nil, safe(err)
	}
	token, err := NewToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err = insertSession(ctx, tx, token, a, true, &now); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, safe(err)
	}
	return s.store.requiredSession(ctx, token)
}

// ModifyTOTP verifies password and a fresh second factor inside the same locked
// transaction that removes the factor or regenerates backup codes.
func (s *Service) ModifyTOTP(ctx context.Context, current *Session, peer, password, code string, remove bool) ([]string, error) {
	if err := current.RequireAuthenticated(); err != nil {
		return nil, err
	}
	if err := s.factorLimit(ctx, current, peer); err != nil {
		return nil, err
	}
	if Password(password) != nil {
		return nil, InvalidCredentials
	}
	a, err := s.store.account(ctx, current.User.Email)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, Unauthenticated
	}
	ok, err := s.passwords.Compare(ctx, password, a.Hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, InvalidCredentials
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	locked, err := s.factorAccount(ctx, tx, current, false, false)
	if err != nil {
		return nil, err
	}
	if a.Hash != locked.Hash || !locked.TOTPEnabled {
		return nil, Conflict
	}
	if err = s.consumeSecurityProof(ctx, tx, a.ID, code); err != nil {
		return nil, err
	}
	var codes []string
	if remove {
		if _, err = tx.Exec(ctx, "UPDATE users SET totp_enabled=false WHERE id=$1", a.ID); err != nil {
			return nil, safe(err)
		}
		if _, err = tx.Exec(ctx, "DELETE FROM auth_totp WHERE user_id=$1", a.ID); err != nil {
			return nil, safe(err)
		}
		if _, err = tx.Exec(ctx, "DELETE FROM auth_recovery_codes WHERE user_id=$1", a.ID); err != nil {
			return nil, safe(err)
		}
	} else {
		codes, err = newRecoveryCodes(ctx, tx, a.ID)
		if err != nil {
			return nil, err
		}
	}
	if err = factorChange(ctx, tx, locked, current); err != nil {
		return nil, err
	}
	return codes, safe(tx.Commit(ctx))
}

// A saved recovery code can replace a lost authenticator for account security
// management, but only alongside the separately verified account password.
func (s *Service) consumeSecurityProof(ctx context.Context, tx pgx.Tx, id, code string) error {
	if len(code) == 6 {
		return s.consumeTOTP(ctx, tx, id, code, false)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != code {
		return invalidFactor
	}
	result, err := tx.Exec(ctx, "UPDATE auth_recovery_codes SET consumed_at=now() WHERE user_id=$1 AND code_hash=$2 AND consumed_at IS NULL", id, tokenHash(code))
	if err != nil {
		return safe(err)
	}
	if result.RowsAffected() != 1 {
		return invalidFactor
	}
	return nil
}
