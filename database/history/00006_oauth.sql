-- +goose Up
CREATE TABLE auth_oauth_identities (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 provider text NOT NULL CHECK(provider IN ('github','google')),
 subject text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(user_id,provider),
 UNIQUE(provider,subject)
);
CREATE TABLE auth_oauth_states (
 state_hash bytea PRIMARY KEY CHECK(octet_length(state_hash)=32),
 session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
 user_id uuid REFERENCES users(id) ON DELETE CASCADE,
 user_version bigint,
 provider text NOT NULL CHECK(provider IN ('github','google')),
 operation text NOT NULL CHECK(operation IN ('login','link')),
 pkce_verifier bytea NOT NULL,
 nonce text NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 CHECK((operation='login' AND user_id IS NULL AND user_version IS NULL) OR (operation='link' AND user_id IS NOT NULL AND user_version IS NOT NULL))
);
CREATE INDEX auth_oauth_states_expiry ON auth_oauth_states(expires_at);
CREATE TABLE auth_oauth_grants (
 token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32),
 session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 user_version bigint NOT NULL,
 provider text NOT NULL CHECK(provider IN ('github','google')),
 subject text NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz
);
CREATE INDEX auth_oauth_grants_expiry ON auth_oauth_grants(expires_at);
-- +goose Down
DROP TABLE auth_oauth_grants;
DROP TABLE auth_oauth_states;
DROP TABLE auth_oauth_identities;
