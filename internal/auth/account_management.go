package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type PendingEmailChange struct {
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type ClosureBlocker struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type ClosureStatus struct {
	Pending      *time.Time       `json:"pending"`
	Blockers     []ClosureBlocker `json:"blockers"`
	RecoveryDays int              `json:"recoveryDays"`
}

// ObserveSession stores display-only client metadata, never trusted identity or
// IP location. Activity writes are bounded to once per five minutes.
func (s *Service) ObserveSession(ctx context.Context, current *Session, agent string) error {
	if current == nil || current.User == nil {
		return nil
	}
	agent = strings.ToValidUTF8(agent, "")
	agent = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, agent)
	for len(agent) > 512 {
		_, n := utf8.DecodeLastRuneInString(agent)
		agent = agent[:len(agent)-n]
	}
	_, err := s.store.pool.Exec(ctx, `UPDATE auth_sessions SET user_agent=COALESCE(user_agent,NULLIF($2,'')),last_seen_at=now() WHERE id=$1 AND revoked_at IS NULL AND (last_seen_at IS NULL OR last_seen_at<now()-interval '5 minutes')`, current.ID, agent)
	return safe(err)
}

func (s *Service) RevokeOtherSessions(ctx context.Context, current *Session) (int64, error) {
	if err := current.RequireAuthenticated(); err != nil {
		return 0, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return 0, safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, false, false)
	if err != nil {
		return 0, err
	}
	for _, q := range []string{`DELETE FROM auth_ceremonies WHERE session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1 AND id<>$2)`, `DELETE FROM auth_oauth_states WHERE session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1 AND id<>$2)`, `DELETE FROM auth_oauth_grants WHERE session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1 AND id<>$2)`} {
		if _, err = tx.Exec(ctx, q, a.ID, current.ID); err != nil {
			return 0, safe(err)
		}
	}
	result, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL`, a.ID, current.ID)
	if err != nil {
		return 0, safe(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, safe(err)
	}
	return result.RowsAffected(), nil
}

func (s *Service) PendingEmail(ctx context.Context, current *Session) (*PendingEmailChange, error) {
	if err := current.RequireAuthenticated(); err != nil {
		return nil, err
	}
	var p PendingEmailChange
	err := s.store.pool.QueryRow(ctx, `SELECT target_email,expires_at FROM auth_email_tokens WHERE user_id=$1 AND purpose='email_change' AND user_version=$2 AND consumed_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 1`, current.User.ID, current.UserVersion).Scan(&p.Email, &p.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, safe(err)
	}
	return &p, nil
}

func (s *Service) RequestEmailChange(ctx context.Context, current *Session, peer, email string) error {
	if err := current.RequireRecent(time.Now()); err != nil {
		return err
	}
	if s.email == nil {
		return Unavailable
	}
	email, err := Email(email)
	if err != nil {
		return err
	}
	if email == current.User.Email {
		return Validation("Enter a different email address.")
	}
	if err = s.store.throttle(ctx, "email-change/user/"+current.User.ID, 5); err != nil {
		return err
	}
	if err = s.store.throttle(ctx, "email-change/ip/"+peer, 10); err != nil {
		return err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, true, false)
	if err != nil {
		return err
	}
	// Never reserve another account's address, disclose its ownership or switch
	// the verified login email before a one-use confirmation.
	var occupied bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&occupied); err != nil {
		return safe(err)
	}
	if occupied {
		return nil
	}
	if _, err = tx.Exec(ctx, `UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose='email_change' AND consumed_at IS NULL`, a.ID); err != nil {
		return safe(err)
	}
	if err = s.issueAccountEmail(ctx, tx, a, "email_change", email, "/confirm-email-change", "Confirm your new Foltivo email", 30*time.Minute); err != nil {
		return err
	}
	return safe(tx.Commit(ctx))
}

func (s *Service) CancelEmailChange(ctx context.Context, current *Session) error {
	if err := current.RequireAuthenticated(); err != nil {
		return err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, false, false)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose='email_change' AND consumed_at IS NULL`, a.ID)
	if err != nil {
		return safe(err)
	}
	return safe(tx.Commit(ctx))
}

func (s *Service) ConfirmEmailChange(ctx context.Context, current *Session, peer, token string) error {
	if err := current.RequireAuthenticated(); err != nil {
		return err
	}
	if !validToken(token) {
		return Validation("This link is invalid or has expired.")
	}
	if err := s.LimitEmailConsumption(ctx, peer); err != nil {
		return err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, false, false)
	if err != nil {
		return err
	}
	var target string
	err = tx.QueryRow(ctx, `UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND token_hash=$2 AND purpose='email_change' AND user_version=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING target_email`, a.ID, tokenHash(token), a.Version).Scan(&target)
	if errors.Is(err, pgx.ErrNoRows) {
		return Validation("This link is invalid or has expired.")
	}
	if err != nil {
		return safe(err)
	}
	// Unique index resolves concurrent confirmations for the same target.
	_, err = tx.Exec(ctx, `UPDATE users SET email=$2,email_verified=true,security_version=security_version+1,updated_at=now() WHERE id=$1`, a.ID, target)
	if err != nil {
		return Conflict
	}
	if err = invalidateAccountAccess(ctx, tx, a.ID); err != nil {
		return err
	}
	if err = s.accountNotice(ctx, tx, a, "Your Foltivo email changed", "Your Foltivo sign-in email was changed. If you did not authorize this, secure your email and contact Foltivo support. Existing sessions have been signed out."); err != nil {
		return err
	}
	return safe(tx.Commit(ctx))
}

func (s *Service) issueAccountEmail(ctx context.Context, tx pgx.Tx, a *account, purpose, target, route, subject string, lifetime time.Duration) error {
	if s.email == nil {
		return Unavailable
	}
	token, err := NewToken()
	if err != nil {
		return err
	}
	body := fmt.Sprintf("Open this link to continue:\n\n%s%s#token=%s\n\nIf you did not request this, ignore this message. This link expires and can be used once.\n", s.email.Origin, route, token)
	data, err := json.Marshal(emailPayload{To: target, Subject: subject, Body: body})
	if err != nil {
		return Unavailable
	}
	encrypted, err := s.email.Secrets.Seal(data, "email-outbox/v1")
	if err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO auth_email_tokens(user_id,purpose,token_hash,expires_at,target_email,user_version) VALUES($1,$2,$3,now()+$4::interval,$5,$6) RETURNING id::text`, a.ID, purpose, tokenHash(token), lifetime.String(), target, a.Version).Scan(&id)
	if err != nil {
		return safe(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_email_outbox(token_id,payload) VALUES($1,$2)`, id, encrypted)
	return safe(err)
}

func invalidateAccountAccess(ctx context.Context, tx pgx.Tx, id string) error {
	for _, q := range []string{`UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, `UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose<>'security_notice' AND consumed_at IS NULL`, `DELETE FROM auth_ceremonies WHERE user_id=$1`, `DELETE FROM auth_oauth_states WHERE user_id=$1 OR session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1)`, `DELETE FROM auth_oauth_grants WHERE user_id=$1 OR session_id IN(SELECT id FROM auth_sessions WHERE user_id=$1)`} {
		if _, err := tx.Exec(ctx, q, id); err != nil {
			return safe(err)
		}
	}
	return nil
}

// Security notices contain no bearer token. An expiring outbox marker reuses the
// durable delivery and encrypted-payload cleanup rather than sending inside the
// transaction or keeping sensitive mail in logs.
func (s *Service) accountNotice(ctx context.Context, tx pgx.Tx, a *account, subject, body string) error {
	if s.email == nil {
		return Unavailable
	}
	marker, err := NewToken()
	if err != nil {
		return err
	}
	data, err := json.Marshal(emailPayload{To: a.Email, Subject: subject, Body: body})
	if err != nil {
		return Unavailable
	}
	encrypted, err := s.email.Secrets.Seal(data, "email-outbox/v1")
	if err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO auth_email_tokens(user_id,purpose,token_hash,expires_at) VALUES($1,'security_notice',$2,now()+interval '7 days') RETURNING id::text`, a.ID, tokenHash(marker)).Scan(&id)
	if err != nil {
		return safe(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_email_outbox(token_id,payload) VALUES($1,$2)`, id, encrypted)
	return safe(err)
}
