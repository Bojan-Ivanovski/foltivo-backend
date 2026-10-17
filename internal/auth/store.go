package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

type account struct {
	User
	Hash        string
	Version     int64
	TOTPEnabled bool
}

func readAccount(row pgx.Row) (*account, error) {
	var a account
	err := row.Scan(&a.ID, &a.Email, &a.Name, &a.EmailVerified, &a.LibraryID, &a.Hash, &a.Version, &a.TOTPEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &a, safe(err)
}

const accountColumns = `u.id::text,u.email,u.name,u.email_verified,l.id::text,u.password_hash,u.security_version,u.totp_enabled`

func (s *Store) account(ctx context.Context, email string) (*account, error) {
	return readAccount(s.pool.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.email=$1`, email))
}

func (s *Store) register(ctx context.Context, name, email, hash string) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return safe(err)
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING RETURNING id::text`, name, email, hash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return safe(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO libraries(user_owner_id) VALUES($1)`, id); err != nil {
		return safe(err)
	}
	return safe(tx.Commit(ctx))
}

func (s *Store) session(ctx context.Context, token string) (*Session, error) {
	if !validToken(token) {
		return nil, nil
	}
	var session Session
	var userID, email, name, libraryID *string
	var verified, totp *bool
	var version *int64
	err := s.pool.QueryRow(ctx, `SELECT s.id::text,s.created_at,s.expires_at,s.recent_auth_at,s.user_version,s.mfa_verified,
u.id::text,u.email,u.name,u.email_verified,l.id::text,u.totp_enabled
FROM auth_sessions s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN libraries l ON l.user_owner_id=u.id
WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()
AND (s.user_id IS NULL OR (s.user_version=u.security_version AND l.id IS NOT NULL))`, tokenHash(token)).Scan(
		&session.ID, &session.CreatedAt, &session.ExpiresAt, &session.RecentAuthAt, &version, &session.MFA,
		&userID, &email, &name, &verified, &libraryID, &totp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, safe(err)
	}
	if userID != nil {
		session.User = &User{ID: *userID, Email: *email, Name: *name, EmailVerified: *verified, LibraryID: *libraryID}
		session.UserVersion = *version
		session.TOTPEnabled = *totp
	}
	session.Token = token
	session.derive()
	return &session, nil
}

func insertSession(ctx context.Context, tx pgx.Tx, token string, a *account, mfa bool, recent *time.Time) (*Session, error) {
	var userID any
	var version any
	lifetime := 30 * time.Minute
	if a != nil {
		userID = a.ID
		version = a.Version
		lifetime = 7 * 24 * time.Hour
		if !a.EmailVerified || (a.TOTPEnabled && !mfa) {
			lifetime = 15 * time.Minute
			recent = nil
		}
	}
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO auth_sessions(token_hash,user_id,user_version,mfa_verified,recent_auth_at,expires_at)
VALUES($1,$2,$3,$4,$5,now()+$6::interval) RETURNING id::text`, tokenHash(token), userID, version, mfa, recent, lifetime.String()).Scan(&id)
	if err != nil {
		return nil, safe(err)
	}
	return &Session{ID: id, Token: token}, nil
}

func (s *Store) anonymous(ctx context.Context) (*Session, error) {
	token, err := NewToken()
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	if _, err = insertSession(ctx, tx, token, nil, false, nil); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, safe(err)
	}
	return s.requiredSession(ctx, token)
}

// rotate consumes the old session atomically. The account row is locked before
// the session row, and the verified password hash is checked again under lock.
func (s *Store) rotate(ctx context.Context, old *Session, a *account) (*Session, error) {
	token, err := NewToken()
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	if a != nil {
		current, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 FOR UPDATE OF u`, a.ID))
		if err != nil {
			return nil, err
		}
		if current == nil || current.Hash != a.Hash || current.Version != a.Version {
			return nil, Conflict
		}
		a = current
	}
	result, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now() WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>now()`, old.ID, tokenHash(old.Token))
	if err != nil {
		return nil, safe(err)
	}
	if result.RowsAffected() != 1 {
		return nil, Conflict
	}
	now := time.Now().UTC()
	if _, err = insertSession(ctx, tx, token, a, false, &now); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, safe(err)
	}
	return s.requiredSession(ctx, token)
}

func (s *Store) requiredSession(ctx context.Context, token string) (*Session, error) {
	current, err := s.session(ctx, token)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, Conflict
	}
	return current, nil
}

func (s *Store) throttle(ctx context.Context, key string, limit int) error {
	var attempts int
	var retry int
	err := s.pool.QueryRow(ctx, `INSERT INTO auth_throttles(key_hash,attempts,resets_at) VALUES($1,1,now()+interval '15 minutes')
ON CONFLICT(key_hash) DO UPDATE SET
attempts=CASE WHEN auth_throttles.resets_at<=now() THEN 1 ELSE LEAST(auth_throttles.attempts+1,100000) END,
resets_at=CASE WHEN auth_throttles.resets_at<=now() THEN now()+interval '15 minutes' ELSE auth_throttles.resets_at END
RETURNING attempts,GREATEST(1,ceil(extract(epoch FROM resets_at-now()))::int)`, tokenHash(key)).Scan(&attempts, &retry)
	if err != nil {
		return safe(err)
	}
	if attempts > limit {
		return &Error{Status: 429, Code: "rate_limited", Message: "Too many attempts. Try again later.", RetryAfter: retry}
	}
	return nil
}
