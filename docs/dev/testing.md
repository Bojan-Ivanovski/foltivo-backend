# Rust testing

Use the built-in Rust test runner with `rstest` for fixtures and parameterized
cases. Use `foltivo-test-support::postgres` when a test needs a real PostgreSQL
server. The shared fixture starts a fresh PostgreSQL 18.6 container for each
test and removes it when the fixture value is dropped.

## Requirements and commands

Install Rust, Docker, and Docker Compose. Docker must be running and accessible
to the current user. Run the whole workspace with:

```sh
cargo test --locked --workspace
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
