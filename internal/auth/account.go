package auth

import (
	"context"
	"time"
)

type SessionSummary struct {
	ID         string     `json:"id"`
	Current    bool       `json:"current"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	UserAgent  *string    `json:"userAgent"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
}

func (s *Service) Profile(ctx context.Context, current *Session, name string) (*User, error) {
	if err := current.RequireAuthenticated(); err != nil {
		return nil, err
	}
	name, err := Name(name)
	if err != nil {
		return nil, err
	}
	result, err := s.store.pool.Exec(ctx, `UPDATE users u SET name=$1,updated_at=now() WHERE u.id=$2 AND u.email_verified=true AND u.security_version=$3
AND EXISTS(SELECT 1 FROM auth_sessions s WHERE s.id=$4 AND s.revoked_at IS NULL AND s.expires_at>now() AND (NOT u.totp_enabled OR s.mfa_verified))`, name, current.User.ID, current.UserVersion, current.ID)
	if err != nil {
		return nil, safe(err)
	}
	if result.RowsAffected() != 1 {
		return nil, Conflict
	}
	user := *current.User
	user.Name = name
	return &user, nil
}

func (s *Service) Sessions(ctx context.Context, current *Session) ([]SessionSummary, error) {
	if err := current.RequireAuthenticated(); err != nil {
		return nil, err
	}
	rows, err := s.store.pool.Query(ctx, `SELECT id::text,created_at,expires_at,user_agent,last_seen_at FROM auth_sessions WHERE user_id=$1 AND user_version=$2 AND revoked_at IS NULL AND expires_at>now()
AND EXISTS(SELECT 1 FROM auth_sessions active JOIN users u ON u.id=active.user_id WHERE active.id=$3 AND active.revoked_at IS NULL AND active.expires_at>now() AND active.user_version=u.security_version AND u.email_verified AND (NOT u.totp_enabled OR active.mfa_verified)) ORDER BY created_at DESC`, current.User.ID, current.UserVersion, current.ID)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	result := []SessionSummary{}
	for rows.Next() {
		var row SessionSummary
		if err := rows.Scan(&row.ID, &row.CreatedAt, &row.ExpiresAt, &row.UserAgent, &row.LastSeenAt); err != nil {
			return nil, safe(err)
		}
		row.Current = row.ID == current.ID
		result = append(result, row)
	}
	return result, safe(rows.Err())
}

func (s *Service) Revoke(ctx context.Context, current *Session, id string) error {
	if err := current.RequireAuthenticated(); err != nil {
		return err
	}
	if !uuidPattern.MatchString(id) {
		return Validation("Enter a valid session identifier.")
	}
	result, err := s.store.pool.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
AND EXISTS(SELECT 1 FROM auth_sessions active JOIN users u ON u.id=active.user_id WHERE active.id=$3 AND active.revoked_at IS NULL AND active.expires_at>now() AND active.user_version=u.security_version AND u.email_verified AND (NOT u.totp_enabled OR active.mfa_verified))`, id, current.User.ID, current.ID)
	if err != nil {
		return safe(err)
	}
	if result.RowsAffected() != 1 {
		return &Error{Status: 404, Code: "not_found", Message: "Session was not found."}
	}
	return nil
}

func (s *Service) Reauthenticate(ctx context.Context, current *Session, peer, password, code string) error {
	if err := current.RequireAuthenticated(); err != nil {
		return err
	}
	if !current.TOTPEnabled && code != "" {
		return Validation("Unexpected authentication code.")
	}
	if err := Password(password); err != nil {
		return InvalidCredentials
	}
	if err := s.store.throttle(ctx, "reauth/ip/"+peer, 30); err != nil {
		return err
	}
	if err := s.store.throttle(ctx, "reauth/user/"+current.User.ID, 10); err != nil {
		return err
	}
	a, err := s.store.account(ctx, current.User.Email)
	if err != nil {
		return err
	}
	if a == nil {
		return Unauthenticated
	}
	match, err := s.passwords.Compare(ctx, password, a.Hash)
	if err != nil {
		return err
	}
	if !match {
		return InvalidCredentials
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	locked, err := s.factorAccount(ctx, tx, current, false, false)
	if err != nil {
		return err
	}
	if locked.Hash != a.Hash {
		return Conflict
	}
	if locked.TOTPEnabled {
		if err = s.consumeSecurityProof(ctx, tx, a.ID, code); err != nil {
			return err
		}
	}
	if locked.TOTPEnabled && len(code) != 6 {
		if err = factorChange(ctx, tx, locked, current); err != nil {
			return err
		}
		// Keep callers such as ChangePassword aligned with this same request's
		// newly verified source version after recovery revoked other sessions.
		current.UserVersion = locked.Version + 1
	}
	_, err = tx.Exec(ctx, "UPDATE auth_sessions SET recent_auth_at=now() WHERE id=$1", current.ID)
	if err != nil {
		return safe(err)
	}
	return safe(tx.Commit(ctx))
}
