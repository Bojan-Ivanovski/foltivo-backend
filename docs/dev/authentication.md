> Rust migration note: #18 carries these policies into Rust with SeaORM and
> SeaORM Migration. Historical delivery/verification statements below describe
> the Go baseline. No Rust build, test, runtime or provider validation was run.
> Library-specific differences and data compatibility are documented in
> [Rust migration notes](rust-migration.md).

# Rust authentication foundation

Backend #18 ports the application-owned authentication selected in #3 to Rust. The REST contract is in
[authentication API](../api/authentication.md). PostgreSQL owns users, password
hashes, personal Library ownership, hashed opaque sessions and throttle counters.
No Node authentication service or application JWT requirement is introduced.
Optional GitHub/Google identities extend existing application-owned accounts without
outsourcing their session or authorization policy. The frontend consumes the same contract from an isolated branch
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

Historical Go fixtures and test coverage remain in Git. They are not Rust
verification or application endpoints.

## Authentication factors

TOTP uses HMAC-SHA1 in the Rust authentication service with six digits, a
30-second period and a one-step clock tolerance. Pending enrollment expires in
10 minutes and cannot affect policy until a code is confirmed. Encrypted secrets
are bound to the account through AES-GCM associated data. An accepted time step
is consumed under the user row lock across every session; use a fresh code for
each sensitive action. Keep server time synchronized. Ten 128-bit random recovery
codes are shown once and stored only as hashes. Recovery consumes one code and
revokes all prior sessions; it never disables TOTP automatically. To replace a
lost authenticator after recovery, the user must supply their password and
another unused saved code for security management. This explicit action can
remove/replace the factor or regenerate backups. Recovery-code reauthentication
also revokes other sessions. Losing every factor and backup never permits an
email-only bypass.

Passkeys use the Rust WebAuthn adapter in src/auth/passkeys.rs, with readers for
the former Go credential and ceremony formats.
The RP ID is the hostname of APP_ORIGIN. For local passkey use set
`APP_ORIGIN=http://localhost:5173` and browse that hostname; numeric IP addresses
cannot be WebAuthn RP IDs. The API can still listen on 127.0.0.1. Production must
use its stable HTTPS hostname: changing it changes the passkey trust boundary.
Discoverable (resident) credentials and user verification are required for
enrollment. Sign-in options omit credential IDs/counts for every email; unknown,
password-only and passkey accounts receive the same public option shape. Finish
still validates the selected account, user handle, credential ownership and UV.
Full library challenge
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

## Verification status

The developer requested #18 without reviews, validation or new tests. No Rust
compatibility, runtime or security verification is claimed. Historical Go checks
do not establish parity for the new implementation; see [status](verification.md).

## Account management completion

Backend #9–#12 extend the foundation with verified email changes, session controls,
optional GitHub/Google linked identities and recoverable account closure. Apply
migrations through `cargo run --bin migrate -- up` before starting this version of the API; startup
never applies migrations automatically.

Email changes retain the old verified sign-in address until a 30-minute,
account-bound link is confirmed by that fully authenticated account. Requesting
requires five-minute recent assurance; confirmation revokes every session and
pending authentication flow. A separate encrypted durable notification is sent to
the old address. Security notices contain no bearer token and survive subsequent
password/reset token invalidation. An occupied target address gets the same
request response without disclosing another account or reserving its address.
A pending request can be inspected or canceled. Links open
`/confirm-email-change#token=…`; frontend removes the fragment and retains the
secret only in page memory. Sign in using the old address before confirmation.

Session listings expose nullable display-only `userAgent` and `lastSeenAt`.
Previously existing sessions can have unknown metadata. User agents are stripped
of invalid UTF-8/control characters and limited to 512 bytes; they are untrusted
labels, not verified device identities. Activity updates occur at most once per
five minutes. No IP address or inferred location is retained. Signing out other
sessions preserves the current session and removes their pending passkey/OAuth
flows; ordinary individual revocation remains supported.

### Optional GitHub and Google identities

Configure the three `OAUTH_GITHUB_*` or `OAUTH_GOOGLE_*` values in `.env.example` as
an all-or-none group. Empty groups disable that provider. Register each exact
browser-visible `/api/v1/auth/providers/{provider}/callback` with its provider;
locally this is the frontend proxy origin, not its internal API target. Production
uses HTTPS. Configuration validation does not provision provider credentials,
callbacks, consent-screen approval or reverse-proxy routing. Store real client
secrets only in deployment secrets or ignored local configuration.

Providers link explicitly to an existing verified Foltivo account after recent
authentication. They never auto-create an account or merge identities based on
matching email. Every Foltivo account retains its password, so unlinking a provider
cannot remove the last primary credential. Google identity tokens are verified
for issuer, audience, expiry and nonce; GitHub identities use the authenticated
stable provider subject. Provider tokens are used for verification and discarded;
repository access/synchronization is a separate feature and grant.

Provider state is single-use, expiring and browser-session bound; PKCE data is
stored encrypted. OAuth login still obeys Foltivo email/MFA policy. The provider
callback issues a short-lived fragment grant instead of writing a new session
cookie. The frontend completes that grant through its usual session mutation
coordinator with current Origin/CSRF checks. This prevents a delayed callback from
overwriting another tab's newer account/session transition. Pending closure,
revocation and security-version changes invalidate outstanding flows.

### Thirty-day account closure

Closure requires fully authenticated five-minute recent assurance and configured
durable email delivery. It records a database deadline 30 days from the request,
revokes every session, invalidates pending tokens/flows, and immediately denies
ordinary password/passkey/provider login. A recovery link is queued atomically;
the user may request another while the window remains open. Links expire after
30 minutes and do not extend the closure deadline.

Recovery requires the email link **and** the existing password **and**, when TOTP
is enrolled, a fresh authenticator code or unused saved recovery code. It preserves
passkeys and enrolled MFA and requires a fresh normal sign-in afterward. There is
no email-only restoration or automatic restoration through ordinary sign-in.
Verified passkey-based closure recovery is not implemented: users who lost their
password or all TOTP/recovery proofs cannot bypass those requirements using this
flow. Keep recovery material before scheduling closure.

The API runs a bounded cleanup worker every minute; multiple processes safely
coordinate using locked account rows. Cleanup and restoration lock the same
account, so only one can commit. After the deadline restoration is unavailable,
even if background cleanup has not run yet. Restoring increments the security
version and consumes outstanding recovery links. Cleanup retries database failures
without exposing identities or credentials in operational logs.

**Current data disposition:** the schema contains the user, its personal Library
stub, authentication sessions/factors, linked provider identities, pending flows
and mail records. Expired closure permanently removes these records, including
encrypted outbox payloads. It does not implement disposition of documents, shared
contributions, organization membership or organizations: those resource tables do
not yet exist. Deletion does not promise removal from retained database backups;
backup retention is an independent deployment policy.

`account_closure_blockers` is the required integration boundary for ownership and
retention restrictions. Closure scheduling and final cleanup both refuse active
blockers; cleanup checks again after acquiring the account lock. Future
organization ownership/content writers must lock the user row before creating or
removing a blocker in the same transaction, including the last-owner rule. Before
those product capabilities are enabled, define their ownership-transfer, content
retention/disposition and cleanup constraints and wire real blockers. Do not infer
that an empty blocker registry implements organizations that are not in the
schema. Unknown non-cascading foreign keys fail cleanup closed rather than
silently deleting unsupported resources.
