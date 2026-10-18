package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

type MailSender interface {
	Send(context.Context, string, string, string) error
}
type emailPayload struct{ To, Subject, Body string }
type EmailDelivery struct {
	Origin  string
	Secrets *Secrets
	Sender  MailSender
}

func (s *Service) ConfigureEmail(delivery *EmailDelivery) { s.email = delivery }

func (s *Service) RequestEmail(ctx context.Context, peer, email, purpose string) error {
	if s.email == nil {
		return Unavailable
	}
	email, err := Email(email)
	if err != nil {
		return err
	}
	if purpose != "verification" && purpose != "reset" {
		return Validation("Invalid email operation.")
	}
	if err = s.store.throttle(ctx, "email/ip/"+peer, 10); err != nil {
		return err
	}
	if err = s.store.throttle(ctx, "email/"+purpose+"/"+email, 5); err != nil {
		return err
	}
	a, err := s.store.account(ctx, email)
	if err != nil {
		return err
	}
	if a == nil || a.ClosureAt != nil || (purpose == "verification" && a.EmailVerified) {
		return nil
	}
	token, err := NewToken()
	if err != nil {
		return err
	}
	route, subject := "/verify-email", "Verify your Foltivo email"
	lifetime := 24 * time.Hour
	if purpose == "reset" {
		route = "/reset-password"
		subject = "Reset your Foltivo password"
		lifetime = 30 * time.Minute
	}
	body := fmt.Sprintf("Open this link to continue:\n\n%s%s#token=%s\n\nIf you did not request this, ignore this message. This link expires and can be used once.\n", s.email.Origin, route, token)
	data, err := json.Marshal(emailPayload{To: email, Subject: subject, Body: body})
	if err != nil {
		return Unavailable
	}
	encrypted, err := s.email.Secrets.Seal(data, "email-outbox/v1")
	if err != nil {
		return err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	// Consistent account-first locking also serializes resets and factor changes.
	locked, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 FOR UPDATE OF u`, a.ID))
	if err != nil {
		return err
	}
	if locked == nil || locked.Email != email || locked.ClosureAt != nil || (purpose == "verification" && locked.EmailVerified) {
		return nil
	}
	a = locked
	if _, err = tx.Exec(ctx, "UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL", a.ID, purpose); err != nil {
		return safe(err)
	}
	var id string
	if err = tx.QueryRow(ctx, `INSERT INTO auth_email_tokens(user_id,purpose,token_hash,expires_at) VALUES($1,$2,$3,now()+$4::interval) RETURNING id::text`, a.ID, purpose, tokenHash(token), lifetime.String()).Scan(&id); err != nil {
		return safe(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO auth_email_outbox(token_id,payload) VALUES($1,$2)`, id, encrypted); err != nil {
		return safe(err)
	}
	return safe(tx.Commit(ctx))
}

// DeliverEmail processes one pending message. Delivery is at least once; retries
// reuse the same single-use link. Failed sends remain queued with bounded backoff.
func (s *Service) DeliverEmail(ctx context.Context) (bool, error) {
	if s.email == nil {
		return false, nil
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return false, safe(err)
	}
	defer tx.Rollback(ctx)
	var id string
	var payload []byte
	var usable bool
	var attempts int
	err = tx.QueryRow(ctx, `SELECT o.id::text,o.payload,(t.consumed_at IS NULL AND t.expires_at>now()),o.attempts FROM auth_email_outbox o JOIN auth_email_tokens t ON t.id=o.token_id WHERE o.completed_at IS NULL AND o.next_attempt_at<=now() ORDER BY o.created_at LIMIT 1 FOR UPDATE OF o SKIP LOCKED`).Scan(&id, &payload, &usable, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, safe(err)
	}
	if usable {
		plain, e := s.email.Secrets.Open(payload, "email-outbox/v1")
		if e != nil {
			return false, e
		}
		var message emailPayload
		if json.Unmarshal(plain, &message) != nil {
			return false, Unavailable
		}
		sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = s.email.Sender.Send(sendCtx, message.To, message.Subject, message.Body)
		cancel()
		if e != nil {
			delay := time.Duration(1<<min(attempts, 8)) * time.Second
			_, err = tx.Exec(ctx, `UPDATE auth_email_outbox SET attempts=attempts+1,next_attempt_at=now()+$2::interval WHERE id=$1`, id, delay.String())
			if err != nil {
				return false, safe(err)
			}
			if err = tx.Commit(ctx); err != nil {
				return false, safe(err)
			}
			return true, Unavailable
		}
	}
	// Remove encrypted token-bearing payload after completion or obsolescence.
	_, err = tx.Exec(ctx, `UPDATE auth_email_outbox SET completed_at=now(),payload=''::bytea WHERE id=$1`, id)
	if err != nil {
		return false, safe(err)
	}
	return true, safe(tx.Commit(ctx))
}

func (s *Service) EmailLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		for i := 0; i < 20; i++ {
			bounded, cancel := context.WithTimeout(ctx, 7*time.Second)
			found, err := s.DeliverEmail(bounded)
			cancel()
			if err != nil || !found {
				if err != nil && ctx.Err() == nil {
					slog.Warn("auth_email_delivery_retry")
				}
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) ConsumeEmail(ctx context.Context, token, purpose, password string) error {
	if !validToken(token) {
		return Validation("This link is invalid or has expired.")
	}
	hash := ""
	var err error
	if purpose == "reset" {
		if err = Password(password); err != nil {
			return err
		}
		hash, err = s.passwords.Hash(ctx, password)
		if err != nil {
			return err
		}
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	var userID string
	// Find identity, then lock user before token, matching issuance/factor ordering.
	err = tx.QueryRow(ctx, `SELECT user_id::text FROM auth_email_tokens WHERE token_hash=$1 AND purpose=$2`, tokenHash(token), purpose).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Validation("This link is invalid or has expired.")
	}
	if err != nil {
		return safe(err)
	}
	var closing bool
	if err = tx.QueryRow(ctx, "SELECT closure_requested_at IS NOT NULL FROM users WHERE id=$1 FOR UPDATE", userID).Scan(&closing); err != nil {
		return safe(err)
	}
	if closing {
		return Validation("This link is invalid or has expired.")
	}
	result, err := tx.Exec(ctx, `UPDATE auth_email_tokens SET consumed_at=now() WHERE token_hash=$1 AND purpose=$2 AND consumed_at IS NULL AND expires_at>now()`, tokenHash(token), purpose)
	if err != nil {
		return safe(err)
	}
	if result.RowsAffected() != 1 {
		return Validation("This link is invalid or has expired.")
	}
	if purpose == "verification" {
		_, err = tx.Exec(ctx, "UPDATE users SET email_verified=true,updated_at=now() WHERE id=$1", userID)
		if err == nil {
			_, err = tx.Exec(ctx, "UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL", userID)
		}
	} else if purpose == "reset" {
		_, err = tx.Exec(ctx, "UPDATE users SET password_hash=$2,security_version=security_version+1,updated_at=now() WHERE id=$1", userID, hash)
		if err == nil {
			_, err = tx.Exec(ctx, "UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL", userID)
		}
		if err == nil {
			_, err = tx.Exec(ctx, "UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose<>'security_notice' AND consumed_at IS NULL", userID)
		}
	} else {
		return Validation("Invalid email operation.")
	}
	if err != nil {
		return safe(err)
	}
	return safe(tx.Commit(ctx))
}

func (s *Service) ChangePassword(ctx context.Context, current *Session, peer, old, password, code string) error {
	if err := s.Reauthenticate(ctx, current, peer, old, code); err != nil {
		return err
	}
	if err := Password(password); err != nil {
		return err
	}
	hash, err := s.passwords.Hash(ctx, password)
	if err != nil {
		return err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 FOR UPDATE OF u`, current.User.ID))
	if err != nil {
		return err
	}
	if a == nil || a.Version != current.UserVersion {
		return Conflict
	}
	var activeID string
	err = tx.QueryRow(ctx, `SELECT id::text FROM auth_sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>now() AND recent_auth_at>now()-interval '5 minutes' FOR UPDATE`, current.ID).Scan(&activeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Conflict
	}
	if err != nil {
		return safe(err)
	}
	_, err = tx.Exec(ctx, "UPDATE users SET password_hash=$2,security_version=security_version+1,updated_at=now() WHERE id=$1", a.ID, hash)
	if err != nil {
		return safe(err)
	}
	_, err = tx.Exec(ctx, "UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1", a.ID)
	if err != nil {
		return safe(err)
	}
	_, err = tx.Exec(ctx, "UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose<>'security_notice' AND consumed_at IS NULL", a.ID)
	if err != nil {
		return safe(err)
	}
	return safe(tx.Commit(ctx))
}

func (s *Service) LimitEmailConsumption(ctx context.Context, peer string) error {
	return s.store.throttle(ctx, "email-consume/ip/"+peer, 20)
}
