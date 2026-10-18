DROP TABLE account_closure_blockers;
UPDATE auth_email_tokens SET consumed_at=COALESCE(consumed_at,now()) WHERE purpose IN ('email_change','closure_recovery','security_notice');
DELETE FROM auth_email_outbox WHERE token_id IN (SELECT id FROM auth_email_tokens WHERE purpose IN ('email_change','closure_recovery','security_notice'));
DELETE FROM auth_email_tokens WHERE purpose IN ('email_change','closure_recovery','security_notice');
ALTER TABLE auth_email_tokens DROP COLUMN target_email, DROP COLUMN user_version;
ALTER TABLE auth_email_tokens DROP CONSTRAINT auth_email_tokens_purpose_check;
ALTER TABLE auth_email_tokens ADD CONSTRAINT auth_email_tokens_purpose_check CHECK(purpose IN ('verification','reset'));
ALTER TABLE auth_sessions DROP CONSTRAINT bounded_user_agent, DROP COLUMN user_agent, DROP COLUMN last_seen_at;
ALTER TABLE users DROP CONSTRAINT closure_dates, DROP COLUMN closure_requested_at, DROP COLUMN closure_expires_at;
