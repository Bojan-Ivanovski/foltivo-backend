# Automated coverage for backend #19

The suite combines the historical Go requirements at
`6fc5145a7f0983dd1a3c92a44216ec9de041df55` (33 top-level tests in 16 files) with
coverage for the later delivered account/provider lifecycle. It preserves the
existing REST contract in `docs/api/authentication.md`; it does not introduce
frontend features or change resource authorization policy.

## Coverage map

| Scope | Executable evidence | What it exercises |
| --- | --- | --- |
| Shared isolation | `tests/common/mod.rs`, all database-backed targets | Per-test containers, bounded SQL readiness, explicit test config, cookie/CSRF client, loopback SMTP, managed browser/process lifetime |
| Config / transport policy | `config::tests`, `tests/configuration.rs` | Defaults, strict origin/proxy/production DB TLS rules, optional/partial provider config, SMTP security/sender rules, safe URL errors and lazy pool construction |
| Validation / secrets | `auth::crypto::tests`, `auth::tests` | Unicode boundaries, identifiers, token/CSRF vectors, independent Go AES-GCM/AAD vectors, integrity failures, production Argon2 and admission, assurance precedence and exact five-minute recent-auth boundary |
| Registration / sessions | `tests/auth_lifecycle.rs` | Generic/idempotent registration and independent personal Libraries, partial state, verification and reset one-use/expiry, password changes, session rotation/restart/metadata, ownership, current/other/bulk revocation and security-version expiry, persistent rate limits |
| HTTP / browser contract | `tests/http_contract.rs`, `http::tests` | Cookie/method/HEAD/Allow/body/media/DTO/duplicate/null limits, Origin before DB, CSRF, partial-state route matrix, no-body DELETE, safe errors/no-store/Retry-After, trust-chain bounds, metadata Unicode |
| TOTP / recovery | `auth::factors::tests`, `tests/factors.rs` | RFC 6238 time-window/replay vectors, expiring pending enrollment, signed-code challenges, hashed one-use recovery/regeneration/removal, session invalidation, MFA retained through reset and closure recovery |
| Passkeys / migration compatibility | `tests/passkeys.rs` | Actual Chromium CTAP2 resident-key/UV registration/assertion, replay/signature/UV/UP/origin/challenge/user-handle rejection, browser/version/expiry binding, decoy shapes, removal, Go-library credential/in-flight ceremony conversion and hybrid metadata/counter preservation |
| GitHub / Google | `auth::oauth::tests` | Controlled token/profile/discovery/JWKS traffic, PKCE/state/browser binding and one-use burn, immutable subjects/conflicts, signed RS256 claim/signature failures, MFA-preserving completion, grant expiry/version/unlink rejection, provider malformed/oversized/status failures |
| Email / SMTP outbox | `tests/account_lifecycle.rs`, `tests/concurrency.rs` | Verified change replacement/cancel/ownership/conflict/expiry, old address and token rollback, encrypted Go-capitalized payloads, real SMTP retry/schedule/obsolescence/erasure, SKIP LOCKED claims |
| Closure / cleanup | `tests/account_lifecycle.rs`, `tests/factors.rs`, `tests/concurrency.rs` | Persisted blockers, fixed thirty-day deadline, password/MFA recovery and no auto-session, replacement-link limits, revocation, final dependent-record cleanup, lock/deadline races |
| Database / migration CLI | `tests/migrations.rs`, `database/tests/mappings.rs` | Real CLI guards/create/status/version/up/down/reset, all Goose prefixes 0–6, latest revert/reapply history, invalid-history rollback, retained data/history/transition marker, reset/up, failed DDL atomicity, advisory lock timeout/cancellation, all fourteen ORM mappings |
| API process / HTTP transport | `tests/process.rs`, `tests/transport.rs` | Live health/readiness and session bootstrap, schema untouched on startup, signal/worker/connection draining, real stalled-header/write/idle deadlines and server usability afterward |
| Cross-flow consistency | `tests/concurrency.rs` | Observed account-lock contention for competing rotation and recovery/email proof consumption, stale security-version denial after lock wait, recovery deadline vs cleanup, independent outbox claims |

## Evidence boundaries

Each test fails if required local infrastructure is missing. Routine provider
checks require no live credentials and never use personal development or
production state. Standard execution remains `cargo test --locked --workspace`,
with `RUST_TEST_THREADS=4` recommended and configured in CI. `CI` / `Verify`
identity and tests-before-release-build ordering are retained.

A green suite proves the named synthetic scenarios on the tested revision and
platform. It does not prove complete Go parity, a coverage percentage, production
TLS/proxy deployment correctness, internet-provider availability, inbox delivery,
every hardware authenticator/browser combination, or future Library/content
ownership rules. SMTP send and PostgreSQL commit are separate operations;
exactly-once external delivery is not claimed. This suite tests the current
persisted closure blockers without inventing unimplemented Organization/content
retention behavior.

The Chromium fixture is a backend protocol test. Frontend UI navigation/state
coordination and device interoperability remain coordinated work in
Bojan-Ivanovski/foltivo-frontend. In-process HTTP tests exercise the existing
shared payload/error/session contract; they do not assert frontend rendering.

## Defects exposed during implementation

The real keep-alive test found that changing the HTTP read phase did not wake a
pending connection, allowing the previous phase timer to delay starting the
idle deadline. The fix explicitly wakes the reader on phase transitions. The
regression asserts actual connection closure within the configured idle bound
and that subsequent connections remain usable. Verification results belong in
`verification.md`; this description alone is not a passing test claim.
