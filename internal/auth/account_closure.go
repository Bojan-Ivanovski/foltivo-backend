package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

func closureBlockers(ctx context.Context, tx pgx.Tx, id string) ([]ClosureBlocker, error) {
	rows, err := tx.Query(ctx, `SELECT code,message FROM account_closure_blockers WHERE user_id=$1 ORDER BY code`, id)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	result := []ClosureBlocker{}
	for rows.Next() {
		var b ClosureBlocker
		if err = rows.Scan(&b.Code, &b.Message); err != nil {
			return nil, safe(err)
		}
		result = append(result, b)
	}
	return result, safe(rows.Err())
}

func (s *Service) AccountClosure(ctx context.Context, current *Session) (*ClosureStatus, error) {
	if err := current.RequireAuthenticated(); err != nil {
		return nil, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, false, false)
	if err != nil {
		return nil, err
	}
	blockers, err := closureBlockers(ctx, tx, a.ID)
	if err != nil {
		return nil, err
	}
	return &ClosureStatus{Blockers: blockers, RecoveryDays: 30}, nil
}

func (s *Service) ScheduleClosure(ctx context.Context, current *Session) (time.Time, error) {
	var expiry time.Time
	if err := current.RequireRecent(time.Now()); err != nil {
		return expiry, err
	}
	// Recovery cannot be offered unless durable email delivery is configured.
	if s.email == nil {
		return expiry, Unavailable
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return expiry, safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := s.factorAccount(ctx, tx, current, true, false)
	if err != nil {
		return expiry, err
	}
	blockers, err := closureBlockers(ctx, tx, a.ID)
	if err != nil {
		return expiry, err
	}
	if len(blockers) > 0 {
		return expiry, &Error{Status: 409, Code: "closure_blocked", Message: "Resolve account ownership and retention blockers before closing this account."}
	}
	err = tx.QueryRow(ctx, `UPDATE users SET closure_requested_at=now(),closure_expires_at=now()+interval '30 days',security_version=security_version+1,updated_at=now() WHERE id=$1 RETURNING closure_expires_at`, a.ID).Scan(&expiry)
	if err != nil {
		return expiry, safe(err)
	}
	if err = invalidateAccountAccess(ctx, tx, a.ID); err != nil {
		return expiry, err
	}
	// Issue the first recovery link atomically with the closure. It expires in 30
	// minutes; another may be requested while the recovery window remains open.
	a.Version++
	if err = s.issueAccountEmail(ctx, tx, a, "closure_recovery", a.Email, "/recover-account", "Recover your Foltivo account", 30*time.Minute); err != nil {
		return expiry, err
	}
	return expiry, safe(tx.Commit(ctx))
}

func (s *Service) RequestClosureRecovery(ctx context.Context, peer, email string) error {
	if s.email == nil {
		return Unavailable
	}
	email, err := Email(email)
	if err != nil {
		return err
	}
	if err = s.store.throttle(ctx, "closure-recovery/ip/"+peer, 10); err != nil {
		return err
	}
	if err = s.store.throttle(ctx, "closure-recovery/email/"+email, 5); err != nil {
		return err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.email=$1 AND u.closure_expires_at>now() FOR UPDATE OF u`, email))
	if err != nil {
		return err
	}
	if a == nil {
		return nil
	}
	if _, err = tx.Exec(ctx, `UPDATE auth_email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose='closure_recovery' AND consumed_at IS NULL`, a.ID); err != nil {
		return safe(err)
	}
	if err = s.issueAccountEmail(ctx, tx, a, "closure_recovery", email, "/recover-account", "Recover your Foltivo account", 30*time.Minute); err != nil {
		return err
	}
	return safe(tx.Commit(ctx))
}

func (s *Service) ConfirmClosureRecovery(ctx context.Context, peer, token, password, code string) error {
	if !validToken(token) {
		return Validation("This recovery link is invalid or has expired.")
	}
	if err := s.store.throttle(ctx, "closure-confirm/ip/"+peer, 20); err != nil {
		return err
	}
	var id string
	err := s.store.pool.QueryRow(ctx, `SELECT user_id::text FROM auth_email_tokens WHERE token_hash=$1 AND purpose='closure_recovery' AND consumed_at IS NULL AND expires_at>now()`, tokenHash(token)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Validation("This recovery link is invalid or has expired.")
	}
	if err != nil {
		return safe(err)
	}
	if err = s.store.throttle(ctx, "closure-confirm/user/"+id, 10); err != nil {
		return err
	}
	a, err := readAccount(s.store.pool.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1`, id))
	if err != nil {
		return err
	}
	if err = Password(password); err != nil {
		return InvalidCredentials
	}
	hash := ""
	if a != nil {
		hash = a.Hash
	}
	match, err := s.passwords.Compare(ctx, password, hash)
	if err != nil {
		return err
	}
	if a == nil || !match {
		return InvalidCredentials
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	locked, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 AND u.closure_expires_at>now() FOR UPDATE OF u`, id))
	if err != nil {
		return err
	}
	if locked == nil || locked.ClosureAt == nil || locked.Hash != a.Hash || locked.Version != a.Version {
		return Conflict
	}
	var tokenID string
	err = tx.QueryRow(ctx, `SELECT id::text FROM auth_email_tokens WHERE user_id=$1 AND token_hash=$2 AND purpose='closure_recovery' AND consumed_at IS NULL AND expires_at>now() AND user_version=$3 FOR UPDATE`, id, tokenHash(token), locked.Version).Scan(&tokenID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Validation("This recovery link is invalid or has expired.")
	}
	if err != nil {
		return safe(err)
	}
	if locked.TOTPEnabled {
		if err = s.consumeSecurityProof(ctx, tx, id, code); err != nil {
			return err
		}
	} else if code != "" {
		return Validation("Unexpected authentication code.")
	}
	_, err = tx.Exec(ctx, `UPDATE users SET closure_requested_at=NULL,closure_expires_at=NULL,security_version=security_version+1,updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return safe(err)
	}
	if err = invalidateAccountAccess(ctx, tx, id); err != nil {
		return err
	}
	return safe(tx.Commit(ctx))
}

// DeleteExpiredAccount deletes only the account-owned tables present in the
// current schema. Future resource/organization integrations must register live
// closure blockers and define disposition before closure is enabled for them.
// Account row locking serializes recovery, new blockers and permanent removal.
func (s *Service) DeleteExpiredAccount(ctx context.Context) (bool, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return false, safe(err)
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `SELECT u.id::text FROM users u WHERE u.closure_expires_at<=now() AND NOT EXISTS(SELECT 1 FROM account_closure_blockers b WHERE b.user_id=u.id) ORDER BY u.closure_expires_at LIMIT 1 FOR UPDATE OF u SKIP LOCKED`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, safe(err)
	}
	// Recheck after obtaining the user lock: the selection statement may have
	// waited for a concurrent blocker writer with an older statement snapshot.
	blockers, err := closureBlockers(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if len(blockers) > 0 {
		return false, nil
	}
	// FK constraints fail closed if future resources are added without an explicit
	// disposition. OAuth, factors and ceremonies use cascading account/session FKs.
	for _, q := range []string{`DELETE FROM auth_email_outbox WHERE token_id IN(SELECT id FROM auth_email_tokens WHERE user_id=$1)`, `DELETE FROM auth_email_tokens WHERE user_id=$1`, `DELETE FROM auth_sessions WHERE user_id=$1`, `DELETE FROM libraries WHERE user_owner_id=$1`, `DELETE FROM users WHERE id=$1`} {
		if _, err = tx.Exec(ctx, q, id); err != nil {
			return false, safe(err)
		}
	}
	return true, safe(tx.Commit(ctx))
}

func (s *Service) ClosureLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		for i := 0; i < 20; i++ {
			bounded, cancel := context.WithTimeout(ctx, 7*time.Second)
			found, err := s.DeleteExpiredAccount(bounded)
			cancel()
			if err != nil || !found {
				if err != nil && ctx.Err() == nil {
					slog.Warn("account_closure_cleanup_retry")
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
