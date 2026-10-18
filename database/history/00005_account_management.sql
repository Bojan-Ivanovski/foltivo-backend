-- +goose Up
ALTER TABLE users ADD COLUMN closure_requested_at timestamptz, ADD COLUMN closure_expires_at timestamptz;
ALTER TABLE users ADD CONSTRAINT closure_dates CHECK ((closure_requested_at IS NULL) = (closure_expires_at IS NULL));
ALTER TABLE auth_sessions ADD COLUMN user_agent text, ADD COLUMN last_seen_at timestamptz;
ALTER TABLE auth_sessions ADD CONSTRAINT bounded_user_agent CHECK (octet_length(user_agent)<=512);
ALTER TABLE auth_email_tokens DROP CONSTRAINT auth_email_tokens_purpose_check;
ALTER TABLE auth_email_tokens ADD CONSTRAINT auth_email_tokens_purpose_check CHECK (purpose IN ('verification','reset','email_change','closure_recovery','security_notice'));
ALTER TABLE auth_email_tokens ADD COLUMN target_email text, ADD COLUMN user_version bigint;
CREATE TABLE account_closure_blockers (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 code text NOT NULL,
 message text NOT NULL,
 PRIMARY KEY(user_id,code)
);
CREATE INDEX users_closure_expiry ON users(closure_expires_at) WHERE closure_expires_at IS NOT NULL;
-- +goose Down
DROP TABLE account_closure_blockers;
UPDATE auth_email_tokens SET consumed_at=COALESCE(consumed_at,now()) WHERE purpose IN ('email_change','closure_recovery','security_notice');
DELETE FROM auth_email_outbox WHERE token_id IN (SELECT id FROM auth_email_tokens WHERE purpose IN ('email_change','closure_recovery','security_notice'));
DELETE FROM auth_email_tokens WHERE purpose IN ('email_change','closure_recovery','security_notice');
ALTER TABLE auth_email_tokens DROP COLUMN target_email, DROP COLUMN user_version;
ALTER TABLE auth_email_tokens DROP CONSTRAINT auth_email_tokens_purpose_check;
ALTER TABLE auth_email_tokens ADD CONSTRAINT auth_email_tokens_purpose_check CHECK(purpose IN ('verification','reset'));
ALTER TABLE auth_sessions DROP CONSTRAINT bounded_user_agent, DROP COLUMN user_agent, DROP COLUMN last_seen_at;
ALTER TABLE users DROP CONSTRAINT closure_dates, DROP COLUMN closure_requested_at, DROP COLUMN closure_expires_at;
