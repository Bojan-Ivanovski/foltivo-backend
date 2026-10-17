-- +goose Up
CREATE TABLE auth_totp (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 secret bytea NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 pending_expires_at timestamptz NOT NULL DEFAULT now()+interval '10 minutes',
 last_step bigint NOT NULL DEFAULT -1
);
CREATE TABLE auth_recovery_codes (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 code_hash bytea NOT NULL CHECK(octet_length(code_hash)=32),
 consumed_at timestamptz,
 PRIMARY KEY(user_id,code_hash)
);
CREATE TABLE auth_passkeys (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 credential_id bytea UNIQUE NOT NULL,
 credential bytea NOT NULL,
 name text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX auth_passkeys_user ON auth_passkeys(user_id);
CREATE TABLE auth_ceremonies (
 session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('registration','login')),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 user_version bigint NOT NULL,
 data jsonb NOT NULL,
 name text NOT NULL DEFAULT '',
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(session_id,kind)
);
-- +goose Down
DROP TABLE auth_ceremonies;
DROP TABLE auth_passkeys;
DROP TABLE auth_recovery_codes;
DROP TABLE auth_totp;
