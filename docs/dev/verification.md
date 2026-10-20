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
