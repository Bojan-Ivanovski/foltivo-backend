# Backend stack

## Confirmed

- **Go** is the backend application language; the required toolchain is recorded
  in [go.mod](../../go.mod).
- The frontend/backend API boundary uses **REST**.
- The module is `github.com/Bojan-Ivanovski/foltivo-backend`.
- Product name: **Foltivo**. Intended public domain: **foltivo.com**. This does not
  establish deployment, API subdomains, mail addresses or authentication callbacks.

## Selected database infrastructure

Backend #2 selects PostgreSQL 18, pgx v5 and Goose v3 with embedded SQL migrations.
Local Docker Compose pins `postgres:18.6-bookworm`; the database is bound to
localhost and uses a named volume. A separate `cmd/migrate` executable applies
reviewed migrations with a PostgreSQL session advisory lock. The API never
migrates on startup. See [database development](database.md) for configuration,
commands, deployment ownership and recovery expectations.

The standard-library HTTP server in cmd/api uses net/http and ServeMux.
`GET /health` returns process liveness; `GET /ready` verifies database connectivity.
HTTP_ADDR overrides :8080. DATABASE_URL is required. SIGINT/SIGTERM shut down
gracefully. A database outage leaves liveness available and readiness unavailable.

## Pending decisions

- Authentication libraries/service composition: backend #3. The application and
  authentication design must respect the developer's Go direction; no Better
  Auth/Node service is selected. Factor, recovery and assurance contracts still
  require analysis.
- The initial server uses net/http and its ServeMux. Additional framework,
  query-layer, job, storage, live collaboration and hosting choices remain open.

Use gofmt for Go source when introduced. Add dependencies, executable commands
and CI checks only when their scope and prerequisites are established; do not
claim a server or test suite exists because a Go module has been initialized.
