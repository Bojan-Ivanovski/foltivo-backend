CREATE TABLE auth_email_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  purpose text NOT NULL CHECK (purpose IN ('verification','reset')),
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX auth_email_tokens_user_idx ON auth_email_tokens(user_id,purpose);
CREATE TABLE auth_email_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_id uuid NOT NULL REFERENCES auth_email_tokens(id),
  payload bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  attempts integer NOT NULL DEFAULT 0,
  completed_at timestamptz
);
CREATE INDEX auth_email_outbox_pending_idx ON auth_email_outbox(next_attempt_at) WHERE completed_at IS NULL;

