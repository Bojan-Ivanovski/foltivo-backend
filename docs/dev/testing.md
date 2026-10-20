# Rust testing

Use the built-in Rust test runner with `rstest` for fixtures and parameterized
cases. Use `foltivo-test-support::postgres` when a test needs a real PostgreSQL
server. The shared fixture starts a fresh PostgreSQL 18.6 container for each
test and removes it when the fixture value is dropped.

## Requirements and commands

Install Rust, Docker, native OpenSSL development headers, Node.js 22 or newer,
and Chromium/Google Chrome. Docker must be running and accessible to the current
user. Run the whole workspace with:

```sh
RUST_TEST_THREADS=4 cargo test --locked --workspace
```

Run a specific package or test target with standard Cargo filters, for example:

```sh
cargo test --locked -p foltivo-database
cargo test --locked -p foltivo-backend test_name
```

Tests requiring PostgreSQL use Testcontainers to start their own disposable
database; they do not read `DATABASE_URL`, load `.env`, or connect to the local
Compose database. Each test gets a random host port, so PostgreSQL tests can run
in parallel without sharing a schema or fixed port. Use only the connection
string from that test's `postgres` fixture. Do not set Testcontainers' keep
containers option for routine test runs.

Example async fixture use:

```rust,ignore
use foltivo_test_support::postgres;
use rstest::rstest;

#[rstest]
#[tokio::test]
async fn database_case(#[future] postgres: foltivo_test_support::TestPostgres) {
    let postgres = postgres.await;
    let database_url = postgres.connection_string();
    // Connect only to this fixture's disposable database.
}
```

The helper uses the same digest-qualified `postgres:18.6-bookworm` image as
`compose.yaml`. Update both references together when changing the local
PostgreSQL image.

Provider credentials are not required. Tests that exercise external provider
flows should use controlled local doubles and fixtures.

## CI

The Verify job runs `cargo test --locked --workspace` before building the
release binaries. PostgreSQL tests start containers through Docker on the
GitHub-hosted Ubuntu runner. No separate database service or persistent volume
is used.


## Application and protocol fixtures

`tests/common/mod.rs` composes the shared container into raw PostgreSQL,
migrated application, SMTP, browser-contract and authenticator fixtures. The
application fixture performs a bounded SQL readiness probe before applying
migrations. Each test owns its database; there is no shared fixed-port service,
Compose volume or ambient `DATABASE_URL`. Application fixtures construct explicit
test configuration; API/migration subprocesses clear the inherited environment.
Background loops are started only by tests which exercise process/worker
behavior. Other tests call a single worker step to arrange outcomes precisely.

Signed WebAuthn tests require Node and a maintained Chromium binary. Set
`FOLTIVO_TEST_CHROMIUM` to its absolute path when it is not on PATH. The helper
also recognizes an existing Playwright Chromium cache; Playwright is not a test
runner or dependency of this suite. Missing Docker, Node or Chromium fails the
corresponding tests rather than silently skipping them. CI provisions Node and
Chrome with commit-pinned setup actions and sets the binary path explicitly.

The authenticator uses an ephemeral loopback origin/profile and Chromium's
CTAP2 virtual authenticator. Tests still run the production server's signature
and user-verification checks. Provider tests use local HTTP doubles and signed
RS256 tokens/JWKS. Only unit-test transport destinations can be overridden;
production provider URLs and issuer/TLS policy are unchanged. SMTP tests use a
loopback protocol peer with real acceptance/rejection responses.

The fixture key material is synthetic. See
[fixture provenance and regeneration](../../tests/fixtures/README.md). Go is
needed only to regenerate the independent historical vectors, not to run tests.

## Determinism and resource limits

Configuration matrices use an explicit value-reader seam, avoiding global env
mutation. TOTP/recent-auth pure decisions accept explicit time for exact boundary
cases. Database expiry/retry tests arrange timestamps inside disposable state;
Tokio time is not presented as a PostgreSQL or Chrono clock. Real transport tests
exercise actual header/write/idle deadlines; the idle test takes roughly one
minute by design.

Concurrency tests hold real account/outbox/advisory locks on independent
connections and observe PostgreSQL waiters before releasing them. They assert
one-use winners, rejected stale versions and persisted final state. They do not
infer contention from scheduling alone.

Use four test threads to bound simultaneous containers, Argon2 work and browser
processes on ordinary CI/local machines. Password tests retain the production
64 MiB/three-iteration/four-lane policy; only test-profile compiler optimization
for Argon2/Blake2 is changed. Test-profile debug symbols/incremental artifacts
are disabled to keep the many integration executables practical on disk.

Container ownership is retained through the test scope. Fixture subprocesses
have bounded lifetimes, kill-on-drop behavior and explicit shutdown where
needed. Failed test runs do not require deleting a development database or
Compose volume. A host crash can still leave temporary browser directories;
remove only directories known to belong to that terminated test run.

For the scenario map and limits of the evidence, see
[automated coverage](testing-coverage.md). Record exact performed commands/results
in the delivery PR and [verification record](verification.md).
