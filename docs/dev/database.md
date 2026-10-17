# PostgreSQL and schema migrations

Backend #2 selects PostgreSQL 18 (local image `postgres:18.6-bookworm`, also pinned
to the verified registry digest in compose.yaml), pgx v5
and Goose v3. SQL migrations are embedded into a dedicated migration executable.
The API never applies migrations. Run one migration job before releasing API
instances; Goose's PostgreSQL session advisory lock serializes competing runners.

## Local startup and shutdown

Install Docker with Compose and the Go toolchain from go.mod. From the repository
root, copy the placeholder configuration and choose a local password:

```sh
cp .env.example .env
# Edit .env: change both database password entries and generate a persistent
# AUTH_ENCRYPTION_KEY (base64-encoded 32 random bytes) for encrypted mail/factors.
docker compose up -d --wait
set -a
. ./.env
set +a
go run ./cmd/migrate status
go run ./cmd/migrate up
go run ./cmd/migrate version
go run ./cmd/api
```

Compose reads `.env` automatically; Go commands use exported process variables.
The `.env` example uses shell assignment syntax so it can also be sourced. Quote
values containing shell metacharacters; URL-encode URL credentials. Keep `.env`
ignored and restrict it to your user. Avoid shell tracing, printing the environment
or `docker compose config` without `--quiet`, which can display secrets.

PostgreSQL binds to localhost only and persists in the project's `postgres_data`
named volume. PostgreSQL 18's volume mount is `/var/lib/postgresql`. The healthcheck
uses `pg_isready`; API readiness additionally verifies an authenticated connection.
`docker compose stop` and `docker compose start --wait` retain the database.
`docker compose down` removes containers/network and retains the volume. To stop
the API gracefully, send SIGINT (Ctrl+C) or SIGTERM; requests get up to ten seconds
to finish before the pool closes.

`GET /health` returns `200 {"status":"ok"}` for process liveness independently
of PostgreSQL. `GET /ready` pings PostgreSQL with a two-second deadline and returns
`200 {"status":"ready"}` or generic `503 {"status":"unavailable"}`. These
endpoints set `Cache-Control: no-store`. Readiness proves connectivity, not schema
compatibility; deployment owns applying the correct migration artifact. The API
can start during a database outage and recover readiness when connections return.

## Configuration and environment separation

| Variable | Meaning |
| --- | --- |
| `DATABASE_URL` | Required PostgreSQL connection URL for API/migration commands. Never passed as a CLI argument or printed. |
| `APP_ENV` | `development`, `test` or `production`; defaults to `production`. Unsafe commands require an explicit development/test value. |
| `HTTP_ADDR` | API bind address; defaults to `:8080`. Local example binds localhost. |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | Local Compose database initialization. Password is required. |
| `POSTGRES_PORT` | Local Compose host port; defaults to `5432`. Update DATABASE_URL if changed. |
| `TEST_DATABASE_URL` | Explicit isolated PostgreSQL URL for integration tests; not read by production commands. |

Use separate databases and credentials for development, automated tests and
production. Production uses externally provisioned PostgreSQL, secret injection
and TLS (`sslmode=verify-full` with the appropriate trusted CA). Compose is local
development infrastructure. Its initialization user owns the local database; use
separate least-privilege application and migration roles in production. Existing
volumes retain their initial database/password: changing Compose environment
variables does not change an initialized database's credentials.

Application boundaries suppress raw pgx/Goose errors because malformed URLs,
authentication errors and SQL details may contain credentials. Error messages
identify the operation; investigate with restricted database/operator tooling.
The pgx connection timeout is five seconds and API pool limit is ten connections.

## Authoring and shipping migrations

```sh
go run ./cmd/migrate create add_example
# Edit internal/migrate/sql/<timestamp>_add_example.sql, then review both directions.
go run ./cmd/migrate up
go build -o bin/migrate ./cmd/migrate
go build -o bin/api ./cmd/api
```

`create` requires the repository root and a lowercase snake_case name. It needs no
database configuration, writes to source using exclusive file creation, and
cannot alter embedded files. Inspect the generated filename for unique ordering
when branches merge. The bootstrap migration is version 1 with `SELECT 1`; Goose
creates its `goose_db_version` history table, and no domain tables are invented.

`up`, `status`, `version`, `down` and `reset` read embedded migrations. `go run`
recompiles current source; a previously built executable sees only the migrations
embedded at build time. Rebuild after authoring SQL. The built migration executable
runs from any directory without SQL files alongside it. Ship API and migration
executables from the same revision and run the migration executable as a separate
controlled deployment job. The full Goose standalone CLI is not required.

Applied historical migrations are immutable. Fix mistakes with new reviewed
migrations. Goose tracks versions and application time, not checksums; review must
enforce immutability. Missing/out-of-order migrations fail rather than being
silently applied. Do not rename/reorder applied migrations or edit migration
history manually as a routine repair.

Each migration is transactional by default: SQL and its applied history entry
commit together or roll back together. Some PostgreSQL operations, such as
`CREATE INDEX CONCURRENTLY`, cannot run inside a transaction. Use Goose's
`-- +goose NO TRANSACTION` only after reviewing interruption/retry behavior;
partial changes may remain after failure. Investigate actual database state,
restore or apply a reviewed repair, and retry only when consistent. SQL functions
with internal semicolons need `StatementBegin`/`StatementEnd` annotations.

The session lock is held for each command on the same database connection.
Acquisition retries every second for up to thirty seconds; unlock retries for up
to five seconds. The operation deadline defaults to five minutes and can be set
with `--timeout 15m` before the command. SIGINT/SIGTERM cancel operations. Session
locks require a direct PostgreSQL connection or a session-pooling proxy; do not
run migrations through transaction pooling. PostgreSQL releases locks if the
connection dies. This protection coordinates these migration runners; it does
not prevent uncoordinated manual DDL.

## Deliberate local rollback and reset

First inspect `status` and independently verify the target database. Review Down
SQL and take a backup if the data matters. Both commands require two deliberate
signals, and production is always refused:

```sh
APP_ENV=development go run ./cmd/migrate --allow-unsafe down
APP_ENV=development go run ./cmd/migrate --allow-unsafe reset
```

`down` reverses one applied migration. `reset` reverses all applied migrations to
version zero; it does not recreate the database or remove Goose history. The
environment guard relies on correct operator configuration and cannot prove a
database is disposable. Never point these commands at production with a false
environment label. For a completely disposable local database, stop all clients
and explicitly run `docker compose down --volumes`, then start/migrate again.
That command permanently deletes the local named volume's data.

Schema reversal does not recover deleted rows. Prefer forward fixes when Down
would lose data; use verified backups and a recovery plan for destructive changes.
Deploy compatible additive schema changes first, roll out code that understands
both old/new forms, then remove obsolete schema in a later release after old API
instances/jobs are retired. Reverting an application binary does not automatically
make an incompatible schema safe. Do not run migrations from each API replica.

## Verification

```sh
go test ./...
go vet ./...
# With an isolated test database (not production):
TEST_DATABASE_URL="$DATABASE_URL" go test -race ./...
```

Integration tests skip unless `TEST_DATABASE_URL` is set. They create uniquely
named schemas in that explicit test database and drop their schemas afterward;
the test role must be allowed to create schemas. Tests cover a clean bootstrap,
repeat application, a second test-only table migration, transactional failure,
rollback/reset and advisory lock contention. Domain probe tables exist only in
isolated test schemas. Unit tests cover safe configuration errors, CLI validation,
rollback guards, readiness deadlines and liveness during outages.

Verify source creation/rebuild separately, run the built executable outside the
repository, and exercise API outage/recovery plus graceful shutdown when changing
the operational setup. Record actual commands/results in the delivery PR.

References: [Goose Provider](https://pkg.go.dev/github.com/pressly/goose/v3),
[Goose advisory locking](https://pkg.go.dev/github.com/pressly/goose/v3/lock),
[pgx](https://github.com/jackc/pgx),
[PostgreSQL image](https://hub.docker.com/_/postgres),
[PostgreSQL supported versions](https://www.postgresql.org/support/versioning/).
