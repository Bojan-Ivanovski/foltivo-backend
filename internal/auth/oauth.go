package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// OAuthProviderConfig holds server-only application credentials. Identity login
// never grants repository scopes and never creates or merges local accounts.
type OAuthProviderConfig struct{ Provider, ClientID, ClientSecret, RedirectURL string }
type oauthConfig struct{ providers map[string]oauth2.Config }
type ProviderSummary struct {
	Provider   string     `json:"provider"`
	Configured bool       `json:"configured"`
	Linked     bool       `json:"linked"`
	LinkedAt   *time.Time `json:"linkedAt,omitempty"`
}

func (s *Service) ConfigureOAuth(configs []OAuthProviderConfig) error {
	result := &oauthConfig{providers: map[string]oauth2.Config{}}
	for _, item := range configs {
		if item.Provider != "github" && item.Provider != "google" {
			return fmt.Errorf("unsupported OAuth provider")
		}
		if item.ClientID == "" && item.ClientSecret == "" && item.RedirectURL == "" {
			continue
		}
		u, err := url.Parse(item.RedirectURL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) || item.ClientID == "" || item.ClientSecret == "" {
			return fmt.Errorf("invalid OAuth configuration for %s", item.Provider)
		}
		if u.Path != "/api/v1/auth/providers/"+item.Provider+"/callback" {
			return fmt.Errorf("invalid OAuth callback path")
		}
		cfg := oauth2.Config{ClientID: item.ClientID, ClientSecret: item.ClientSecret, RedirectURL: item.RedirectURL}
		if item.Provider == "github" {
			cfg.Endpoint = oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams}
		} else {
			cfg.Endpoint = oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", AuthStyle: oauth2.AuthStyleInParams}
			cfg.Scopes = []string{oidc.ScopeOpenID}
		}
		result.providers[item.Provider] = cfg
	}
	s.oauth = result
	return nil
}

func (s *Service) Providers(ctx context.Context, current *Session) ([]ProviderSummary, error) {
	result := []ProviderSummary{}
	for _, provider := range []string{"github", "google"} {
		item := ProviderSummary{Provider: provider}
		if s.oauth != nil {
			_, item.Configured = s.oauth.providers[provider]
		}
		if current.User != nil {
			if err := current.RequireAuthenticated(); err != nil {
				return nil, err
			}
			err := s.store.pool.QueryRow(ctx, `SELECT created_at FROM auth_oauth_identities WHERE user_id=$1 AND provider=$2`, current.User.ID, provider).Scan(&item.LinkedAt)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, safe(err)
			}
			item.Linked = item.LinkedAt != nil
		}
		result = append(result, item)
	}
	return result, nil
}

func (s *Service) BeginOAuth(ctx context.Context, current *Session, peer, provider, operation string) (string, error) {
	if s.oauth == nil {
		return "", Unavailable
	}
	cfg, ok := s.oauth.providers[provider]
	if !ok {
		return "", Unavailable
	}
	if operation != "link" && operation != "login" {
		return "", Validation("Invalid provider operation.")
	}
	if operation == "link" {
		if err := current.RequireRecent(time.Now()); err != nil {
			return "", err
		}
	} else if current.User != nil {
		return "", Conflict
	}
	if s.email == nil {
		return "", Unavailable
	}
	if err := s.store.throttle(ctx, "oauth/start/"+peer, 30); err != nil {
		return "", err
	}
	state, err := NewToken()
	if err != nil {
		return "", err
	}
	verifier, err := NewToken()
	if err != nil {
		return "", err
	}
	nonce, err := NewToken()
	if err != nil {
		return "", err
	}
	sealed, err := s.email.Secrets.Seal([]byte(verifier), "oauth-pkce/v1")
	if err != nil {
		return "", err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return "", safe(err)
	}
	defer tx.Rollback(ctx)
	var userID, version any
	if operation == "link" {
		a, err := s.factorAccount(ctx, tx, current, true, false)
		if err != nil {
			return "", err
		}
		userID = a.ID
		version = a.Version
	} else {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM auth_sessions WHERE id=$1 AND token_hash=$2 AND user_id IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, current.ID, tokenHash(current.Token)).Scan(&id); err != nil {
			return "", Conflict
		}
	}
	// A new attempt supersedes previous attempts from this browser/provider.
	_, err = tx.Exec(ctx, `DELETE FROM auth_oauth_states WHERE session_id=$1 AND provider=$2`, current.ID, provider)
	if err != nil {
		return "", safe(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_oauth_states(state_hash,session_id,user_id,user_version,provider,operation,pkce_verifier,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '5 minutes')`, tokenHash(state), current.ID, userID, version, provider, operation, sealed, nonce)
	if err != nil {
		return "", safe(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return "", safe(err)
	}
	challenge := sha256.Sum256([]byte(verifier))
	return cfg.AuthCodeURL(state, oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256"), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("prompt", "select_account")), nil
}

// FinishOAuth burns the browser-bound state before external calls. Failures can
// only be retried with a fresh authorization attempt, never replayed callbacks.
type OAuthCallback struct {
	Operation string
	Grant     string
}

func (s *Service) FinishOAuth(ctx context.Context, current *Session, peer, provider, state, code string) (*OAuthCallback, error) {
	if s.oauth == nil || s.email == nil {
		return nil, Unavailable
	}
	cfg, ok := s.oauth.providers[provider]
	if !ok {
		return nil, Unavailable
	}
	if !validToken(state) || len(code) > 4096 {
		return nil, Validation("Provider confirmation is invalid or expired.")
	}
	if err := s.store.throttle(ctx, "oauth/callback/"+peer, 30); err != nil {
		return nil, err
	}
	var operation, nonce string
	var encrypted []byte
	var userID *string
	var version *int64
	err := s.store.pool.QueryRow(ctx, `UPDATE auth_oauth_states o SET consumed_at=now() FROM auth_sessions s WHERE o.state_hash=$1 AND o.provider=$2 AND o.session_id=$3 AND s.id=o.session_id AND s.token_hash=$4 AND s.revoked_at IS NULL AND s.expires_at>now() AND o.expires_at>now() AND o.consumed_at IS NULL AND (o.user_id IS NULL OR (o.user_id=s.user_id AND o.user_version=s.user_version)) RETURNING o.operation,o.pkce_verifier,o.nonce,o.user_id::text,o.user_version`, tokenHash(state), provider, current.ID, tokenHash(current.Token)).Scan(&operation, &encrypted, &nonce, &userID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, Validation("Provider confirmation is invalid or expired.")
	}
	if err != nil {
		return nil, safe(err)
	}
	if code == "" {
		return nil, Validation("Provider confirmation was cancelled. Start again.")
	}
	if operation == "link" && (current.User == nil || userID == nil || version == nil || current.User.ID != *userID || current.UserVersion != *version) {
		return nil, Conflict
	}
	if operation == "login" && current.User != nil {
		return nil, Conflict
	}
	verifier, err := s.email.Secrets.Open(encrypted, "oauth-pkce/v1")
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	exchangeCtx := context.WithValue(ctx, oauth2.HTTPClient, client)
	token, err := cfg.Exchange(exchangeCtx, code, oauth2.SetAuthURLParam("code_verifier", string(verifier)))
	if err != nil {
		return nil, Validation("Provider confirmation failed. Start again.")
	}
	subject, err := oauthSubject(exchangeCtx, client, provider, cfg.ClientID, nonce, token)
	if err != nil {
		return nil, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	if operation == "link" {
		a, err := s.factorAccount(ctx, tx, current, true, false)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth_oauth_identities(user_id,provider,subject) VALUES($1,$2,$3)`, a.ID, provider, subject)
		if err != nil {
			return nil, &Error{Status: 409, Code: "provider_conflict", Message: "This provider is already linked to an account."}
		}
		if err = tx.Commit(ctx); err != nil {
			return nil, safe(err)
		}
		return &OAuthCallback{Operation: "link"}, nil
	}
	a, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id JOIN auth_oauth_identities i ON i.user_id=u.id WHERE i.provider=$1 AND i.subject=$2 FOR UPDATE OF u`, provider, subject))
	if err != nil {
		return nil, err
	}
	if a == nil || !a.EmailVerified || a.ClosureAt != nil {
		return nil, InvalidCredentials
	}
	// Recheck after locking the account so unlink and closure cannot race login.
	var linked bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth_oauth_identities WHERE user_id=$1 AND provider=$2 AND subject=$3)`, a.ID, provider, subject).Scan(&linked)
	if err != nil {
		return nil, safe(err)
	}
	if !linked {
		return nil, InvalidCredentials
	}
	var activeID string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM auth_sessions WHERE id=$1 AND token_hash=$2 AND user_id IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, current.ID, tokenHash(current.Token)).Scan(&activeID); err != nil {
		return nil, Conflict
	}
	grant, err := NewToken()
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_oauth_grants(token_hash,session_id,user_id,user_version,provider,subject,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '2 minutes')`, tokenHash(grant), current.ID, a.ID, a.Version, provider, subject)
	if err != nil {
		return nil, safe(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, safe(err)
	}
	return &OAuthCallback{Operation: "login", Grant: grant}, nil
}

func oauthSubject(ctx context.Context, client *http.Client, provider, clientID, nonce string, token *oauth2.Token) (string, error) {
	invalid := Validation("Provider identity could not be verified. Start again.")
	if provider == "google" {
		raw, ok := token.Extra("id_token").(string)
		if !ok {
			return "", invalid
		}
		issuer, err := oidc.NewProvider(ctx, "https://accounts.google.com")
		if err != nil {
			return "", Unavailable
		}
		identity, err := issuer.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, raw)
		if err != nil || identity.Nonce != nonce || identity.Subject == "" {
			return "", invalid
		}
		return identity.Subject, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return "", Unavailable
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Foltivo")
	response, err := client.Do(req)
	if err != nil {
		return "", Unavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", invalid
	}
	var identity struct {
		ID int64 `json:"id"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&identity) != nil || identity.ID <= 0 {
		return "", invalid
	}
	return strconv.FormatInt(identity.ID, 10), nil
}

func (s *Service) UnlinkOAuth(ctx context.Context, current *Session, provider string) error {
	if provider != "github" && provider != "google" {
		return Validation("Unknown provider.")
	}
	if err := current.RequireRecent(time.Now()); err != nil {
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
	// All accounts retain a password. Refuse removal if future schema changes
	// introduce provider-only users without another established login method.
	if a.Hash == "" {
		return Validation("Set a password before removing this sign-in method.")
	}
	result, err := tx.Exec(ctx, `DELETE FROM auth_oauth_identities WHERE user_id=$1 AND provider=$2`, a.ID, provider)
	if err != nil {
		return safe(err)
	}
	if result.RowsAffected() != 1 {
		return &Error{Status: 404, Code: "not_found", Message: "Provider is not linked."}
	}
	_, err = tx.Exec(ctx, `DELETE FROM auth_oauth_states WHERE user_id=$1 AND provider=$2`, a.ID, provider)
	if err != nil {
		return safe(err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM auth_oauth_grants WHERE user_id=$1 AND provider=$2`, a.ID, provider); err != nil {
		return safe(err)
	}
	return safe(tx.Commit(ctx))
}

// CompleteOAuth is the only provider-login cookie mutation. The frontend calls
// it through the same cross-tab coordinator used for password and passkey login.
func (s *Service) CompleteOAuth(ctx context.Context, current *Session, peer, token string) (*Session, error) {
	if current.User != nil {
		return nil, Conflict
	}
	if !validToken(token) {
		return nil, Validation("Provider sign-in expired. Start again.")
	}
	if err := s.store.throttle(ctx, "oauth/complete/"+peer, 30); err != nil {
		return nil, err
	}
	var userID string
	err := s.store.pool.QueryRow(ctx, `SELECT user_id::text FROM auth_oauth_grants WHERE token_hash=$1 AND session_id=$2 AND consumed_at IS NULL AND expires_at>now()`, tokenHash(token), current.ID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, Validation("Provider sign-in expired. Start again.")
	}
	if err != nil {
		return nil, safe(err)
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, safe(err)
	}
	defer tx.Rollback(ctx)
	a, err := readAccount(tx.QueryRow(ctx, `SELECT `+accountColumns+` FROM users u JOIN libraries l ON l.user_owner_id=u.id WHERE u.id=$1 FOR UPDATE OF u`, userID))
	if err != nil {
		return nil, err
	}
	if a == nil || !a.EmailVerified || a.ClosureAt != nil {
		return nil, InvalidCredentials
	}
	var activeID string
	err = tx.QueryRow(ctx, `SELECT id::text FROM auth_sessions WHERE id=$1 AND token_hash=$2 AND user_id IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, current.ID, tokenHash(current.Token)).Scan(&activeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, Conflict
	}
	if err != nil {
		return nil, safe(err)
	}
	// Account lock serializes unlink, closure and security-version changes. The
	// grant must still correspond to a currently linked immutable identity.
	var provider, subject string
	err = tx.QueryRow(ctx, `UPDATE auth_oauth_grants g SET consumed_at=now() WHERE g.token_hash=$1 AND g.session_id=$2 AND g.user_id=$3 AND g.user_version=$4 AND g.consumed_at IS NULL AND g.expires_at>now() AND EXISTS(SELECT 1 FROM auth_oauth_identities i WHERE i.user_id=g.user_id AND i.provider=g.provider AND i.subject=g.subject) RETURNING provider,subject`, tokenHash(token), current.ID, a.ID, a.Version).Scan(&provider, &subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, Validation("Provider sign-in expired. Start again.")
	}
	if err != nil {
		return nil, safe(err)
	}
	_, err = tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now() WHERE id=$1`, current.ID)
	if err != nil {
		return nil, safe(err)
	}
	sessionToken, err := NewToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err = insertSession(ctx, tx, sessionToken, a, false, &now); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, safe(err)
	}
	return s.store.requiredSession(ctx, sessionToken)
}
