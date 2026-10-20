# Verification status

For backend #18 the developer explicitly requested the full Rust migration
without reviews, verification, validation commands or creation of tests.

Accordingly no Rust tests were created and no builds, tests, lint, browser/API,
provider, SMTP, migration or database checks were run for this migration. Existing
Go tests are preserved in Git with the original implementation, not presented as
Rust coverage. Historical Go verification does not establish Rust parity.

The workflow file now builds the Rust executables when triggered. It has not
been triggered as part of the local migration. No CI result is claimed.

The source targets the same behavior described in
[the API contract](../api/authentication.md), [authentication](authentication.md)
and [migration notes](rust-migration.md). Any future verification work requires
its own authorization and should report actual results and limitations.

## Local live startup — 2026-10-19

The developer subsequently authorized running the replacement live and fixing
startup issues. `cargo run --locked --bin api` compiled and started the Rust
server using the existing ignored local configuration. Existing PostgreSQL and
Mailpit services were used. The existing frontend was started with Vite on 5173.

Observed live requests:

- GET http://127.0.0.1:8080/health: 200, status ok.
- GET http://127.0.0.1:8080/ready: 200, status ready.
- GET http://localhost:5173/api/v1/auth/session: 200, state anonymous, through the
  frontend proxy to Rust.

No tests were created or run. No migration command, history adoption, database
reset or deployment was performed. Session bootstrap creates an ordinary anonymous
session record. These observations establish local startup/connectivity and
session bootstrap only, not full authentication/account parity. The compiler
reported two unused imports and unused fields in the verified identity-token DTO;
there were no compilation errors.

## Automated coverage follow-up

Backend #19 tracks proper Rust unit, integration, protocol, migration and
concurrency coverage and CI integration. Creating that ticket does not introduce
or execute tests.

## Test tooling — backend #23

The workspace now pins rstest and Testcontainers for test development and
provides a shared fixture that starts a disposable PostgreSQL 18.6 container.
The CI Verify job runs `cargo test --locked --workspace` before building the
executables. This configures the tooling and execution path; it does not add
behavioral tests or establish backend parity. No Rust tests were run as part of
this tooling change. See the [testing guide](testing.md).

## Coverage checkpoint — backend #19, 2026-10-20

The developer selected the layered testing approach and authorized full #19
implementation, including test creation and execution. Work is on
`maintenance/19-rust-coverage` in its dedicated worktree. Child scopes #29–#39
have native parent/dependency links, selected-solution/findings attachments and
Project metadata. Work remains paused at the developer's request; this is a
checkpoint, not a claim that #19 is ready to close.

Performed locally before the pause:

- `RUST_TEST_THREADS=4 cargo test --locked --workspace`: 101 passed, zero
  failed/ignored. This includes real disposable PostgreSQL, local SMTP/provider
  doubles, Chromium CTAP2 signatures/legacy Go vectors, migration CLI and live
  socket/process checks.
- `cargo build --locked --release --workspace --bins`: passed. One existing
  warning remains for deserialized identity-token fields used by validation.
- `cargo fmt --all --check`, `git diff --check` and
  `node --check tests/fixtures/authenticator.mjs`: passed when run.
- Compared all six preserved Goose up SQL bodies with the embedded migration
  SQL after normalizing whitespace/Goose annotations: matched.
- After the full run, refined the SMTP fixture to observe a worker reaching
  DATA before cancellation, replacing a scheduling delay. The targeted
  `smtp_timeout_is_bounded_and_background_workers_cancel_without_committing_partial_delivery`
  test passed on that refinement. The other affected fixture consumers have not
  yet been rerun after that final test-support change.

The real keep-alive test initially failed beyond its configured idle bound.
Waking the pending reader on phase changes restored actual closure at sixty
seconds; the full suite includes this regression. No personal/deployed database,
live provider credentials, deployment or remote CI execution was used or
claimed. Build artifacts are outside source control.

Resume with verification of the final shared SMTP-fixture change across its
consumers, a final scope/evidence review against #19 and the
[coverage map](testing-coverage.md), remaining ticket/documentation cleanup, and
PR preparation. Do not close #19 or its children solely because this checkpoint
is pushed. The developer merges.
