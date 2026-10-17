package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
)

type passkeyUser struct {
	*account
	credentials []wa.Credential
}

func (u passkeyUser) WebAuthnID() []byte                   { return []byte(u.ID) }
func (u passkeyUser) WebAuthnName() string                 { return u.Email }
func (u passkeyUser) WebAuthnDisplayName() string          { return u.Name }
func (u passkeyUser) WebAuthnCredentials() []wa.Credential { return u.credentials }

func (s *Service) ConfigurePasskeys(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return err
	}
	s.webAuthn, err = wa.New(&wa.Config{RPID: parsed.Hostname(), RPDisplayName: "Foltivo", RPOrigins: []string{origin}, AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}, AttestationPreference: protocol.PreferNoAttestation})
	s.webOrigin = origin
	return err
}
func (s *Service) credentialPurpose(id string, kid []byte) string {
	return "passkey/" + id + "/" + base64.RawURLEncoding.EncodeToString(kid)
}
func (s *Service) credentialBytes(id string, c *wa.Credential) ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, Unavailable
	}
	if s.email == nil {
		return nil, Unavailable
	}
	return s.email.Secrets.Seal(data, s.credentialPurpose(id, c.ID))
}
func (s *Service) loadPasskeyUser(ctx context.Context, tx pgx.Tx, a *account) (*passkeyUser, error) {
	if s.email == nil {
		return nil, Unavailable
	}
	rows, err := tx.Query(ctx, "SELECT credential_id,credential FROM auth_passkeys WHERE user_id=$1 ORDER BY created_at", a.ID)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	user := &passkeyUser{account: a, credentials: []wa.Credential{}}
	for rows.Next() {
		var kid, data []byte
		if err = rows.Scan(&kid, &data); err != nil {
			return nil, safe(err)
		}
		data, err = s.email.Secrets.Open(data, s.credentialPurpose(a.ID, kid))
		if err != nil {
			return nil, err
		}
		var c wa.Credential
		if json.Unmarshal(data, &c) != nil {
			return nil, Unavailable
		}
		user.credentials = append(user.credentials, c)
	}
	return user, safe(rows.Err())
}

func (s *Service) BeginPasskey(ctx context.Context, current *Session, peer, kind, value string) (any, error) {
	if s.webAuthn == nil {
		return nil, Unavailable
	}
	var a *account
	var err error
	name := ""
	if kind == "registration" {
		if err = current.RequireRecent(time.Now()); err != nil {
			return nil, err
		}
		name, err = Name(value)
		if err != nil {
			return nil, err
		}
		if err = s.factorLimit(ctx, current, peer); err != nil {
			return nil, err
		}
	} else if kind == "login" {
		if current.State != "anonymous" {
			return nil, Conflict
		}
		email, e := Email(value)
		if e != nil {
			return nil, InvalidCredentials
		}
		if err = s.store.throttle(ctx, "passkey/ip/"+peer, 30); err != nil {
			return nil, err
		}
		if err = s.store.throttle(ctx, "passkey/email/"+email, 10); err != nil {
			return nil, err
		}
		// A new begin invalidates any previous login ceremony, including when
		// this email has no passkey. Responses must not disclose that state.
		if _, err = s.store.pool.Exec(ctx, "DELETE FROM auth_ceremonies WHERE session_id=$1 AND kind='login'", current.ID); err != nil {
			return nil, safe(err)
		}
		a, err = s.store.account(ctx, email)
		if err != nil {
			return nil, err
		}
		if a == nil {
			return s.decoyAssertion()
		}
	} else {
		return nil, Validation("Unknown passkey operation.")
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	if kind == "registration" {
		a, err = s.factorAccount(ctx, tx, current, true, false)
		if err != nil {
			return nil, err
		}
	} else {
		a, err = readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 FOR UPDATE OF u`, a.ID))
		if err != nil {
			return nil, err
		}
		if a == nil {
			return nil, InvalidCredentials
		}
		if err = anonymousActive(ctx, tx, current); err != nil {
			return nil, err
		}
	}
	user, err := s.loadPasskeyUser(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	var options any
	var data *wa.SessionData
	if kind == "registration" {
		if len(user.credentials) >= 10 {
			return nil, Validation("Remove a passkey before adding another.")
		}
		excludes := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
		for _, c := range user.credentials {
			excludes = append(excludes, c.Descriptor())
		}
		options, data, err = s.webAuthn.BeginRegistration(user, wa.WithRegistrationOrigin(s.webOrigin), wa.WithExclusions(excludes))
	} else {
		if len(user.credentials) == 0 {
			return s.decoyAssertion()
		}
		options, data, err = s.webAuthn.BeginLogin(user, wa.WithLoginOrigin(s.webOrigin), wa.WithUserVerification(protocol.VerificationRequired))
	}
	if err != nil {
		return nil, Validation("Unable to start passkey authentication.")
	}
	// Keep all SessionData fields exactly as the library generated them. The DB
	// expiry also bounds ceremonies when the library uses a zero Expires value.
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, Unavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_ceremonies(session_id,kind,user_id,user_version,data,name,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '5 minutes') ON CONFLICT(session_id,kind) DO UPDATE SET user_id=excluded.user_id,user_version=excluded.user_version,data=excluded.data,name=excluded.name,expires_at=excluded.expires_at`, current.ID, kind, a.ID, a.Version, encoded, name)
	if err != nil {
		return nil, safe(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, safe(err)
	}
	return options, nil
}

func anonymousActive(ctx context.Context, tx pgx.Tx, current *Session) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM auth_sessions WHERE id=$1 AND token_hash=$2 AND user_id IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, current.ID, tokenHash(current.Token)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Conflict
	}
	return safe(err)
}

func (s *Service) FinishPasskey(ctx context.Context, current *Session, peer, kind string, body []byte) (*Session, error) {
	if s.webAuthn == nil {
		return nil, Unavailable
	}
	if kind == "registration" {
		if err := current.RequireRecent(time.Now()); err != nil {
			return nil, err
		}
	} else if kind != "login" || current.State != "anonymous" {
		return nil, Conflict
	}
	if err := s.store.throttle(ctx, "passkey-finish/ip/"+peer, 30); err != nil {
		return nil, err
	}
	// Autocommit DELETE deliberately consumes even malformed/invalid attempts.
	// A client must begin a new ceremony after any failed finish.
	var id, name string
	var version int64
	var encoded []byte
	err := s.store.pool.QueryRow(ctx, `DELETE FROM auth_ceremonies WHERE session_id=$1 AND kind=$2 AND expires_at>now() RETURNING user_id::text,user_version,data,name`, current.ID, kind).Scan(&id, &version, &encoded, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, invalidFactor
	}
	if err != nil {
		return nil, safe(err)
	}
	var data wa.SessionData
	if json.Unmarshal(encoded, &data) != nil {
		return nil, Unavailable
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	var a *account
	if kind == "registration" {
		a, err = s.factorAccount(ctx, tx, current, true, false)
		if err != nil {
			return nil, err
		}
		if a.ID != id || a.Version != version {
			return nil, Conflict
		}
	} else {
		a, err = readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 FOR UPDATE OF u`, id))
		if err != nil {
			return nil, err
		}
		if a == nil || a.Version != version {
			return nil, Conflict
		}
		if err = anonymousActive(ctx, tx, current); err != nil {
			return nil, err
		}
	}
	user, err := s.loadPasskeyUser(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	var credential *wa.Credential
	if kind == "registration" {
		if len(user.credentials) >= 10 {
			return nil, Validation("Remove a passkey before adding another.")
		}
		parsed, e := protocol.ParseCredentialCreationResponseBytes(body)
		if e != nil {
			return nil, invalidFactor
		}
		credential, err = s.webAuthn.CreateCredential(user, data, parsed)
	} else {
		parsed, e := protocol.ParseCredentialRequestResponseBytes(body)
		if e != nil {
			return nil, invalidFactor
		}
		credential, err = s.webAuthn.ValidateLogin(user, data, parsed)
	}
	if err != nil || credential == nil || !credential.Flags.UserVerified || credential.Authenticator.CloneWarning {
		return nil, invalidFactor
	}
	stored, err := s.credentialBytes(a.ID, credential)
	if err != nil {
		return nil, err
	}
	if kind == "registration" {
		result, e := tx.Exec(ctx, `INSERT INTO auth_passkeys(user_id,credential_id,credential,name) VALUES($1,$2,$3,$4) ON CONFLICT(credential_id) DO NOTHING`, a.ID, credential.ID, stored, name)
		if e != nil {
			return nil, safe(e)
		}
		if result.RowsAffected() != 1 {
			return nil, Conflict
		}
		if err = factorChange(ctx, tx, a, current); err != nil {
			return nil, err
		}
		return nil, safe(tx.Commit(ctx))
	}
	result, err := tx.Exec(ctx, "UPDATE auth_passkeys SET credential=$3 WHERE user_id=$1 AND credential_id=$2", a.ID, credential.ID, stored)
	if err != nil {
		return nil, safe(err)
	}
	if result.RowsAffected() != 1 {
		return nil, Conflict
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

type PasskeySummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}
type SecuritySummary struct {
	TOTPEnabled            bool             `json:"totpEnabled"`
	RecoveryCodesRemaining int              `json:"recoveryCodesRemaining"`
	Passkeys               []PasskeySummary `json:"passkeys"`
}

func (s *Service) Security(ctx context.Context, current *Session) (*SecuritySummary, error) {
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
	result := &SecuritySummary{TOTPEnabled: a.TOTPEnabled, Passkeys: []PasskeySummary{}}
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM auth_recovery_codes WHERE user_id=$1 AND consumed_at IS NULL", a.ID).Scan(&result.RecoveryCodesRemaining); err != nil {
		return nil, safe(err)
	}
	rows, err := tx.Query(ctx, "SELECT id::text,name,created_at FROM auth_passkeys WHERE user_id=$1 ORDER BY created_at", a.ID)
	if err != nil {
		return nil, safe(err)
	}
	for rows.Next() {
		var key PasskeySummary
		if err = rows.Scan(&key.ID, &key.Name, &key.CreatedAt); err != nil {
			rows.Close()
			return nil, safe(err)
		}
		result.Passkeys = append(result.Passkeys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, safe(err)
	}
	return result, safe(tx.Commit(ctx))
}
func (s *Service) RemovePasskey(ctx context.Context, current *Session, id string) error {
	if err := current.RequireRecent(time.Now()); err != nil {
		return err
	}
	if !uuidPattern.MatchString(id) {
		return Validation("Invalid passkey identifier.")
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
	// Every current account retains its password credential, so removing a
	// passkey cannot remove the last primary authentication method.
	result, err := tx.Exec(ctx, "DELETE FROM auth_passkeys WHERE id=$1 AND user_id=$2", id, a.ID)
	if err != nil {
		return safe(err)
	}
	if result.RowsAffected() != 1 {
		return &Error{Status: 404, Code: "not_found", Message: "Passkey was not found."}
	}
	if err = factorChange(ctx, tx, a, current); err != nil {
		return err
	}
	return safe(tx.Commit(ctx))
}

// Unknown and password-only accounts receive equally usable-looking options.
// No ceremony is stored for these options, so finish always fails generically.
func (s *Service) decoyAssertion() (any, error) {
	challenge, err := NewToken()
	if err != nil {
		return nil, err
	}
	credential, err := NewToken()
	if err != nil {
		return nil, err
	}
	origin, err := url.Parse(s.webOrigin)
	if err != nil {
		return nil, Unavailable
	}
	return map[string]any{"publicKey": map[string]any{"challenge": challenge, "rpId": origin.Hostname(), "timeout": 60000, "userVerification": "required", "allowCredentials": []any{map[string]string{"type": "public-key", "id": credential}}}}, nil
}
