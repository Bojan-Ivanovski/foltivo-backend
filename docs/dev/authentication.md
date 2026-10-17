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

Registration creates an unverified account without signing it in and queues a
verification email. Password login returns verification_required until the link
is consumed; protected endpoints remain unavailable. Verification revokes pending
sessions and requires a fresh login. Reset links revoke all
sessions but preserve enrolled factors. TOTP/recovery and user-verified passkeys are implemented. There is no public verification bypass or token-debug
endpoint.

## Verification and recovery delivery

Set a persistent AUTH_ENCRYPTION_KEY containing 32 random bytes encoded as base64.
Pending outbox payloads and factor secrets use AES-GCM with purpose-bound
associated data. Replacing the key without migrating encrypted records loses
pending mail/factor access; store it securely outside the database and plan key
rotation explicitly. No encryption key or production password is committed.

Tokens are random, purpose-bound, expiring and single-use; their lookup records
contain hashes. Outbox payloads contain only encrypted mail until delivery or
obsolescence, then are cleared. API202 means queued, not delivered. A background
worker uses SKIP LOCKED and bounded SMTP, retrying transient failures with backoff
while logging only a safe operation name. Delivery is at least once; repeated
mail contains the same single-use link. A newer request invalidates older links.
Changing/resetting passwords revokes sessions and outstanding email tokens.

Local Docker Compose includes Mailpit v1.31.6 at localhost:1025 (SMTP) and
localhost:8025 (inbox). Configure SMTP_ADDR, SMTP_FROM and SMTP_REQUIRE_TLS=false
only for loopback development. Production requires explicit SMTP settings and
STARTTLS with certificate validation; SMTP_USERNAME/PASSWORD are optional paired
credentials, never logged. APP_ORIGIN controls fragment-token links. The real
frontend consumes those tokens from the fragment, not URL query logs.

The core-only test fixture can still bypass email verification through trusted
SQL inside isolated tests; that is not an application endpoint. Lifecycle tests
must separately verify real mail transport and token consumption.

## Authentication factors

TOTP uses [pquerna/otp](https://github.com/pquerna/otp) with six digits, a
30-second period and a one-step clock tolerance. Pending enrollment expires in
10 minutes and cannot affect policy until a code is confirmed. Encrypted secrets
are bound to the account through AES-GCM associated data. An accepted time step
is consumed under the user row lock across every session; use a fresh code for
each sensitive action. Keep server time synchronized. Ten 128-bit random recovery
codes are shown once and stored only as hashes. Recovery consumes one code and
revokes all prior sessions; it never disables TOTP automatically.

Passkeys use [go-webauthn/webauthn v0.18.2](https://pkg.go.dev/github.com/go-webauthn/webauthn@v0.18.2/webauthn).
The RP ID is the hostname of APP_ORIGIN. For local passkey use set
`APP_ORIGIN=http://localhost:5173` and browse that hostname; numeric IP addresses
cannot be WebAuthn RP IDs. The API can still listen on 127.0.0.1. Production must
use its stable HTTPS hostname: changing it changes the passkey trust boundary.
User verification is required for enrollment and sign-in. Full library challenge
state is persisted for five minutes, bound to the browser session, ceremony,
account and security version. A finish attempt consumes the ceremony even when
invalid. Origin, RP, signature and UV validation are delegated to the library;
cloned-authenticator warnings are rejected. Full credential records are encrypted
with account and credential ID as associated data, and updated after successful
assertions. Each account supports up to ten named credentials. A verified passkey
can satisfy MFA, but cannot bypass email verification. Every account retains its
password credential; deleting a passkey cannot remove its last primary method.

Factor changes require current trusted assurance, revoke other sessions and
ceremonies, and retain the verified current browser with an updated security
version. No lost-all-factors email-only recovery exists. User/Organization Library
resource permissions are separate from this authentication assurance.

## Browser transport and deployment

Use same-origin /api requests through the frontend proxy, credentials included.
Ordinary session refreshes do not rewrite the existing cookie, so a late read
cannot overwrite a cookie rotated by a concurrent account change.
Obtain the current session and CSRF token from GET /api/v1/auth/session before
mutations. All mutations require an exact APP_ORIGIN Origin and the current
X-CSRF-Token. Session cookies are HttpOnly, SameSite=Lax and host-only. Production
uses Secure __Host cookies, an HTTPS APP_ORIGIN, TRUSTED_TLS_TERMINATION=true and
PostgreSQL sslmode=verify-full. The deployment must actually provide trusted TLS
termination; the flag is not TLS implementation. Local HTTP is restricted to
loopback origins. Migration commands do not need browser-origin configuration.

The server uses the direct peer for throttling unless that peer matches an
explicit `TRUSTED_PROXY_CIDRS` entry. Production requires this comma-separated
list for the actual TLS proxies, preferably exact /32 or /128 addresses. Never
trust an entire client network or a global /0. The proxy must strip incoming
X-Forwarded-For or append its verified peer; forwarding client metadata verbatim
is unsafe. Keep the API network-restricted to those proxies. The server validates
bounded bare-IP chains from right to left and uses the first untrusted hop;
untrusted direct peers cannot supply client addresses. Invalid/missing/ambiguous
metadata falls back to the direct peer bucket, so proxy configuration must be
verified before production traffic. RFC Forwarded and arbitrary other headers
are ignored. Operational logs are structured JSON with safe
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

Run the commands in [verification](verification.md),
including TEST_DATABASE_URL against a dedicated database. Core integration tests
use isolated schemas and trusted test-only SQL to verify partial-state boundaries;
that fixture is not an application email-verification implementation. Live email/browser tests exercise real transport and single-use token workflows.
