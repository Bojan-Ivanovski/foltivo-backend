# Rust backend migration — #18

## Baseline and intent

The parity baseline is Go develop revision
`6fc5145a7f0983dd1a3c92a44216ec9de041df55`. Git retains that implementation and
its historical tests. The replacement stays in the same repository, with the same
PostgreSQL database and frontend REST contract.

The developer selected Rust, SeaORM and SeaORM Migration, superseding Ent in #17.
The developer requested the full implementation without reviews, validation or
new tests. No test, build, lint, runtime, database or browser verification is
claimed for this migration. Source translation is not evidence of verified parity.

## Ownership

- `src/bin/api.rs`: process lifecycle and background worker ownership.
- `src/server.rs`: HTTP/1 transport, connection deadlines and graceful draining.
- `src/http.rs`: existing browser/API boundary, strict request decoder and cookies.
- `src/auth/`: identity/session, account, email, factors, OAuth and passkeys.
- `src/config.rs` and `src/mailer.rs`: process configuration, connection construction,
  and bounded SMTP transport.
- `database/`: SeaORM mappings, SeaORM Migration registration and preserved SQL.

Ordinary entity reads/inserts use SeaORM entities and ActiveModels. Explicit
PostgreSQL statements through SeaORM connections remain for atomic conditional
updates, account-first locks, token consumption and SKIP LOCKED workers. There
is no parallel SQLx migration runner or application-startup migration.

## Behavior carried into the implementation

- Health/readiness, trusted proxy handling, exact Origin and CSRF policy, strict
  bounded JSON, opaque cookie sessions and the current REST routes.
- Registration, verification, passwords, session metadata and revocation, recent
  authentication, TOTP, recovery codes and passkeys.
- Existing-account GitHub/Google linking/login, immutable subjects, PKCE/nonces,
  single-use browser-bound state, and coordinated provider completion.
- Verified email changes, thirty-day closure/recovery, live closure blockers,
  encrypted durable mail with retry and expired-account cleanup.
- Current fourteen-table schema, six historical migrations, data-preserving
  migration-history adoption and guarded local down/reset operations.

## Compatibility handling

Keep DATABASE_URL, APP_ORIGIN, AUTH_ENCRYPTION_KEY and provider callback URLs
stable. The encryption implementation uses the existing AES-256-GCM nonce-prefix
layout and associated-data purpose strings. Argon2id hashes retain PHC encoding
and the existing memory/iterations/parallelism settings. CSRF uses the original
HMAC purpose and token encoding. Encrypted mail retains capitalized Go JSON keys.

The WebAuthn adapter reads historical Go credential JSON, decodes its COSE public
key and flags/counter into the Rust library representation, and encrypts the updated
representation on a successful credential update. Existing Go-only metadata is
retained in an additive hybrid record, with counters and flags synchronized. User handles remain the UTF-8
UUID string bytes used by Go. Existing unexpired Go ceremonies are adapted to
Rust state while preserving their challenge, policy, account/version, origin and
expiry boundaries. Newly begun ceremonies persist Rust state. No mass credential
reset or database mutation is performed merely by installing the source.

The native WebAuthn library depends on OpenSSL; Linux builds need pkg-config and
OpenSSL development headers. Application and migration source are Rust.

## Cutover

Stop the old API and workers before adopting migration history. Run the explicit
`adopt-goose` command once for an existing Goose database, then `up`, using the
commands in database.md. For a fresh database use `up` directly. Do not run the
old Goose writer again after adoption: SeaORM owns subsequent history.

The original Go revision is available in Git. Existing Go passkey records retain their original fields alongside an additive
Rust representation. Credentials newly registered through Rust use the Rust
format, so returning to Go after new enrollment still requires reverse credential
conversion; a binary rollback alone is insufficient for those new records. Preserve pre-cutover
backups and keys. New schema changes have their own compatibility requirements.

No commits, pushes, database migration execution or deployment are implied by the
local source replacement.
