# Authentication contract — version 1

Selected by the orchestrator under the user's autonomous development directive.
Go owns authentication. Frontend and backend implement this contract together;
changes require coordinating both consumers. Backend #3 owns this design.

## Transport and state

REST prefix: `/api/v1`. JSON request bodies are bounded and strictly validated.
Use same-origin browser requests (`credentials: include`); Vite proxies /api to
the local backend. Production serves/proxies /api under the application origin.
No permissive credentialed CORS or browser bearer tokens/localStorage sessions.

`GET /auth/session` bootstraps/resolves an opaque HttpOnly cookie session and
returns this shape (all identity and assurance are server-derived):

```json
{
  "state": "anonymous",
  "user": null,
  "csrfToken": "session-bound-token",
  "methods": {"password": true, "totp": true, "passkey": true}
}
```

Other states are `verification_required`, `mfa_required`, `authenticated`. User,
when present, is `{id,email,name,emailVerified,libraryId}`; optional identity fields
must not authorize resource access. Authenticated means the enabled policy is
satisfied. The frontend additionally models resolving/unavailable locally; API
failure must never become anonymous success or a mock identity.

Every mutation requires exact trusted Origin and `X-CSRF-Token` from the current
session, including login/register/logout. The cookie is Secure in production,
HttpOnly, SameSite=Lax, Path=/ and has no broad Domain. Sessions rotate after
login/MFA transitions; frontend refetches session after successful non-session
mutations, discards outdated requests and clears protected state before notifying
other consumers of actor/access changes. The server stores only a hash of the
opaque cookie token, applies expiry/revocation and does not log secrets.

Errors: `{ "error": { "code": "invalid_credentials", "message": "…" } }`.
Use 400 malformed/validation, 401 unauthenticated, 403 verification/MFA/CSRF or
permission requirement, 409 stale/conflicting operation, 429 throttle (with
Retry-After), 503 unavailable. Messages are safe and useful; never include raw
SQL, credentials, token links or factor secrets. All auth responses are no-store.

## Initial account endpoints

| Method/path (under /api/v1) | Request | Successful response |
| --- | --- | --- |
| GET /auth/session | None | 200 session shape above; creates an anonymous CSRF-capable session when needed |
| POST /auth/register | `{name,email,password}` | 202 `{message}`; generic check-email response, does not grant authenticated access or disclose duplicate account existence |
| POST /auth/login | `{email,password}` | 200 session shape; verification_required or mfa_required until satisfied |
| POST /auth/logout | `{}` | 200 new anonymous session shape; old session revoked |
| GET /me | None | 200 `{user}` only for fully authenticated verified sessions; otherwise401/403 |
| POST /auth/verification/resend | `{email}` | 202 generic `{message}` |
| POST /auth/verification/confirm | `{token}` | 200 `{message}`; single-use verification, pending sessions revoked; sign in again |
| POST /auth/password/forgot | `{email}` | 202 generic `{message}` |
| POST /auth/password/reset | `{token,password}` | 200 `{message}`; single-use token, all user sessions revoked, enrolled MFA preserved |
| POST /auth/reauthenticate | `{password,code?}` | 200 `{message}`; recent server-verified assurance, code required if TOTP enrolled |
| PATCH /auth/profile | `{name}` | 200 `{user}`; authenticated account only |
| POST /auth/password/change | `{currentPassword,password,code?}` | 200 `{message}`; password and required factor verified; all sessions revoked, sign in again |
| GET /auth/sessions | None | 200 `{sessions:[{id,current,createdAt,expiresAt}]}` |
| DELETE /auth/sessions/{id} | None | 200 `{message}`; owned sessions only, revoke current allowed with resulting sign-out |

Passwords: 15–128 Unicode characters, no silent trimming/truncation. Email and
name validation/canonicalization are enforced server-side; name is a display
field, not immutable account identity. Hashing uses bounded Argon2id work and
secure random salts. Session management and email/login/challenge rate limits
must survive process restarts. Use only explicitly trusted proxy CIDRs and validated forwarding chains.

Verification/reset mail links use `/verify-email#token=…` and
`/reset-password#token=…` under configured APP_ORIGIN. Frontend removes the token
from the address after capture and never places it into telemetry or returnTo.
SMTP delivery is real; local Mailpit captures messages for development/testing.
No public token-debug endpoint. Production requires explicit secure SMTP settings.

## TOTP and recovery

| Method/path | Request | Successful response |
| --- | --- | --- |
| POST /auth/totp/enroll | `{}` | 200 `{secret,uri}`; recent authentication required, pending secret expires and is not yet enabled |
| POST /auth/totp/confirm | `{code}` | 200 `{recoveryCodes:[…]}`; verified activation and one-time plaintext code display |
| POST /auth/mfa/challenge | `{code}` or `{recoveryCode}` | 200 session shape; atomically consume code and rotate the pending session |
| POST /auth/totp/remove | `{password,code}` | 200 `{message}`; verified recent assurance, session revocation/rotation |
| POST /auth/recovery-codes/regenerate | `{password,code}` | 200 `{recoveryCodes:[…]}`; old codes invalidated |
| GET /auth/security | None | 200 `{totpEnabled,recoveryCodesRemaining,passkeys:[{id,name,createdAt}]}` |

Encrypt stored TOTP secrets with a persistent environment-provided key; store
recovery codes hashed. Verify enrollment before enabling. Challenge codes cannot
be replayed in a time window; backup codes are consumed transactionally. Password
reset/email verification never clear MFA. If all enrolled methods and recovery
codes are lost, do not provide an email-only bypass. Factor changes recheck
current session and revoke/rotate as required; no stale pending-session upgrade.

## Passkeys

Use go-webauthn/webauthn. Require user verification and validate RP ID/origin.
Challenges are short-lived, one-use and bound to the initiating browser session
and ceremony. A credential does not itself grant resource permissions.

| Method/path | Request | Successful response |
| --- | --- | --- |
| POST /auth/passkeys/register/begin | `{name}` | 200 standard WebAuthn creation options |
| POST /auth/passkeys/register/finish | standard credential JSON | 200 `{message}` |
| POST /auth/passkeys/login/begin | `{email}` | 200 standard WebAuthn assertion options |
| POST /auth/passkeys/login/finish | standard credential JSON | 200 session shape |
| DELETE /auth/passkeys/{id} | None | 200 `{message}`; owned credential, recent assurance |

Enrollment/removal requires recent authenticated assurance. User-verified passkey
login may satisfy required second-factor assurance only after server validation;
email verification is still required. Display passkey UI only when methods.passkey
is true and the browser supports WebAuthn. Never use credential IDs or client
flags as proof of authentication. The initial account remains password-capable;
removing a credential must not remove the last usable sign-in method.

## Authorization and boundaries

Unverified/MFA-pending sessions have only the narrow verification/challenge/logout
capabilities required to finish sign-in. `/me`, settings, factor enrollment and
future content APIs require the corresponding verified state. Personal Library
ownership is provisioned idempotently with the user; no organization enrollment
is required. Resource sharing/organization administration remains separate work.

The initial foundation enables email/password, TOTP/recovery and validated
passkeys. OAuth login, email changes/account closure and organization UI remain
separate product deliveries; do not show nonfunctional controls or claim those
features are implemented. Existing sample discovery is explicitly isolated from
live auth: real account identity must never be fed into fixture access lists, and
API failures must never silently select a preview account.
