# Go authentication foundation

Backend #3 selects an in-application Go design. The REST contract is in
[authentication API](../api/authentication.md). PostgreSQL owns users, password
hashes, personal Library ownership, hashed opaque sessions and throttle counters.
No Node authentication service, JWT requirement or external identity provider is
introduced. The frontend consumes the same contract from an isolated branch
based on its merged Foltivo rebrand.

## Delivery slices

- #4: core identity/session and protected API, Argon2id, Origin/CSRF protection,
  profile/session management and recent-authentication boundary.
- #5: real email verification/recovery and password changes.
- #6: TOTP/recovery-code and WebAuthn/passkey lifecycle.
- #7: repeatable CI/integration and whole-system verification.

At the core-only stage registration creates an unverified account without signing
it in. Password login returns verification_required and cannot access /me or
settings until email verification is implemented. Capability flags remain false
for unsupported methods; later slices enable them only with working APIs. There
is no public verification bypass or production token-debug endpoint.

## Browser transport and deployment

Use same-origin /api requests through the frontend proxy, credentials included.
Obtain the current session and CSRF token from GET /api/v1/auth/session before
mutations. All mutations require an exact APP_ORIGIN Origin and the current
X-CSRF-Token. Session cookies are HttpOnly, SameSite=Lax and host-only. Production
uses Secure __Host cookies, an HTTPS APP_ORIGIN, TRUSTED_TLS_TERMINATION=true and
PostgreSQL sslmode=verify-full. The deployment must actually provide trusted TLS
termination; the flag is not TLS implementation. Local HTTP is restricted to
loopback origins. Migration commands do not need browser-origin configuration.

The server trusts its direct peer address for throttling and ignores arbitrary
forwarding headers. Deploying behind a proxy requires reviewing shared-peer rate
limits or an explicitly trusted-proxy address design; do not trust user-supplied
X-Forwarded-For as a workaround. Operational logs are structured JSON with safe
known event names; no passwords, cookie tokens, email links or driver details.

## Security invariants

- Only hashes of cryptographically random opaque session tokens are persisted.
  CSRF tokens derive through standard HMAC; knowing a CSRF token does not reveal
  the HttpOnly session bearer.
- Passwords use Argon2id with random salts and bounded memory-heavy concurrency;
  unknown-account login performs an equivalent dummy-hash comparison.
- Session rotation consumes the old session atomically and checks the current
  account credential/security version under lock. Current verification and
  factor policy are derived from trusted source data on each resolution.
- Unverified and pending-MFA sessions cannot access protected endpoints.
  Sensitive actions require recent server-verified assurance.
- Mutations recheck current session/source policy at persistence boundaries.
  Listing or deleting sessions cannot access another account's sessions.
- Durable throttle counters survive application restarts. Auth errors are generic
  and JSON bodies are bounded and reject unknown fields/nonobject input.
- Every account gets one independently owned personal Library. Organization
  membership is not required. Resource sharing/authorization remains a distinct
  boundary and is not inferred from account identity.

## Verification

Run the commands in [verification](verification.md) once that guide is integrated,
including TEST_DATABASE_URL against a dedicated database. Core integration tests
use isolated schemas and trusted test-only SQL to verify partial-state boundaries;
that fixture is not an application email-verification implementation. Later
email/browser tests must exercise real transport and single-use token workflows.
