# PostgreSQL and SeaORM Migration

PostgreSQL 18 remains the database. The backend uses SeaORM for data access and
SeaORM Migration for explicit schema execution. All database artifacts stay in
`database/` inside this repository. The API never runs migrations.

## Configuration and local startup

Install Rust, Docker Compose and native OpenSSL build prerequisites. Copy
`.env.example` to ignored `.env`, choose a database password, and generate a
persistent base64-encoded 32-byte AUTH_ENCRYPTION_KEY. Keep credentials out of Git,
logs and shell tracing. URL-encode credentials in DATABASE_URL.

```sh
docker compose up -d --wait
set -a
. ./.env
set +a
cargo run --bin migrate -- up
cargo run --bin api
```

Compose reads `.env`; the executables read exported variables. PostgreSQL binds
to loopback and persists in the existing `postgres_data` volume. Changing Compose
credentials does not change an initialized volume's database credentials.
`docker compose down` retains that volume. Do not delete it to migrate languages.

| Variable | Meaning |
| --- | --- |
| DATABASE_URL | Required PostgreSQL URL; never logged or passed in command examples. |
| APP_ENV | development, test or production; defaults to production. |
| HTTP_ADDR | API address, default :8080. |
| APP_ORIGIN | Exact browser origin for cookies, CSRF and email links. |
| POSTGRES_DB / POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_PORT | Local Compose initialization and host binding. |
| AUTH_ENCRYPTION_KEY | Existing persistent encryption key; keep stable across cutover. |

Production requires PostgreSQL TLS with `sslmode=verify-full`, an HTTPS origin,
TRUSTED_TLS_TERMINATION=true and actual trusted proxy CIDRs. Use separate
least-privilege application and migration roles. SQL and connection errors are
redacted at application boundaries. The application pool is lazy, with ten
connections and five-second connect/acquire timeouts; readiness has a two-second
bound, and liveness does not depend on a successful connection.

## Transitioning an existing Goose database

The first six migrations retain the original statements. Original Goose files
are preserved under `database/history/`; SeaORM uses separately embedded up/down
files under `database/migrations/`.

Stop the Go API/workers and other migration writers. Take the normal database
backup and retain its encryption key. With the same DATABASE_URL exported:

```sh
cargo run --bin migrate -- adopt-goose
cargo run --bin migrate -- up
cargo run --bin migrate -- status
cargo run --bin migrate -- version
```

`adopt-goose` reads the last recorded applied/reverted state for each Goose
version. It accepts only a contiguous applied prefix of the six known baseline
migrations and an empty SeaORM ledger, then records equivalent SeaORM migration
names in one transaction. It does not execute application DDL or delete the
Goose ledger. A separate foltivo_migration_transition metadata marker records
adoption, including version-zero adoption, and survives a local reset so future
up commands do not mistake it for an unadopted database. Unexpected versions/history fail closed. Existing schema is assumed
to correspond to its history; this command is not a schema repair tool.

Fresh databases have no Goose ledger and use `up` directly. If Goose history is
present without adopted SeaORM history, ordinary commands refuse to proceed.
After adoption, SeaORM is the sole history writer: do not resume Goose execution.

## Commands and authoring

```sh
cargo run --bin migrate -- create add_example
# Edit database/migrations/<timestamp>_add_example.up.sql and .down.sql.
# Register the ordered pair in database/src/lib.rs.
cargo run --bin migrate -- up
cargo build --release --workspace --bins
```

The `create` command needs no database and must run from the repository root. It
uses exclusive file creation and lowercase snake_case names. SQL is embedded;
rebuild the migration executable when changing registered sources. Ship
`target/release/migrate` and `target/release/api` from the same revision.

Commands: up, status, version, adopt-goose, create NAME, down and reset. Put flags
before the command: `--timeout 15m` changes the default five-minute deadline.
SIGINT/SIGTERM cancel operations. Migration operations and ledger changes run
inside a transaction protected by a PostgreSQL advisory transaction lock using
the original Goose lock identifier. Acquisition is bounded by a thirty-second
lock timeout. The lock is released on transaction completion/connection loss.

Applied migration SQL is immutable. Keep baseline names stable and add new
registered migrations for changes. The runner does not support nontransactional
DDL such as CREATE INDEX CONCURRENTLY; use a separately designed operational
change when required rather than weakening transaction guarantees implicitly.

## Deliberate development rollback

```sh
APP_ENV=development cargo run --bin migrate -- --allow-unsafe down
APP_ENV=development cargo run --bin migrate -- --allow-unsafe reset
```

Both require development/test plus --allow-unsafe; production is refused. Down
reverses one migration; reset reverses all SeaORM-applied migrations. Neither
restores deleted data. Environment labels are operator-supplied, so they do not
prove a target is disposable. Prefer forward repairs and retain backups.

No database operations or migration validation were performed during #18, at the
developer's explicit request. See [migration limitations](rust-migration.md).
