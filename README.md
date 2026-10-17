# Foltivo Backend

Go backend for **Foltivo**, a Markdown-first workspace for connected knowledge,
writing and collaboration. The selected product domain is **foltivo.com**.

This repository contains a Go REST API, local PostgreSQL infrastructure and an
embedded Goose schema migration command and an Go account/session layer with queued verification/recovery email.
See [authentication](docs/dev/authentication.md) for delivery status and security
boundaries; factor lifecycle integration is still in progress.

## Development

Install the Go version specified in [go.mod](go.mod), then work from this directory.
The module uses `github.com/Bojan-Ivanovski/foltivo-backend`. Follow the
[database development guide](docs/dev/database.md) for configuration, migration
authoring, production expectations and rollback/recovery.

Set up local PostgreSQL and start the API:

```sh
cp .env.example .env
# Edit .env: choose a local database password and set AUTH_ENCRYPTION_KEY
# to a persistent base64-encoded 32-byte random key (openssl rand -base64 32).
docker compose up -d --wait
set -a
. ./.env
set +a
go run ./cmd/migrate up
go run ./cmd/api
```

Open the frontend through its Vite development server with APP_ORIGIN matching
that origin. Local verification/reset email is captured at http://localhost:8025.
Mail requests are durably queued; SMTP failures retry rather than losing links.
Keep the encryption key stable across restarts and separate from database backups.

`GET http://localhost:8080/health` returns HTTP 200 with JSON:

```json
{"status":"ok"}
```

This is a process liveness endpoint; it does not check database or external-service
readiness. `GET /ready` returns 200 when PostgreSQL responds and 503 during a
database outage. The API never runs migrations itself. Set `HTTP_ADDR` to override
the default `:8080`, for example:

```sh
HTTP_ADDR=127.0.0.1:8081 go run ./cmd/api
```

`docker compose down` stops local PostgreSQL and retains its data volume. Ctrl+C
or SIGTERM gracefully stops the API. Run `go test ./...` for unit tests; the
database guide explains opt-in PostgreSQL integration verification.

The application boundary is a Go REST API. Authentication, authorization and live
collaboration designs require their own analysis and selection.

## Product and work tracking

- [Frontend repository](https://github.com/Bojan-Ivanovski/foltivo-frontend)
- [Account and authentication decision](https://github.com/Bojan-Ivanovski/foltivo-frontend/issues/7)
- [Development process](docs/dev/process.md)
- [Authentication contract](docs/api/authentication.md)
- [Contributing](CONTRIBUTING.md)
- [Ticket hierarchy and starting order](docs/dev/ticket-hierarchy.md)
- [Repository agent instructions](AGENTS.md)

User Libraries support independent personal work; Organization Libraries support
shared organizational work. Libraries own Folios, and optional Books reference
Folios without granting access. Working revisions, Git commits and published
Folio versions are separate identities. The frontend's approved content-model
and release decisions remain the reference until explicitly revised.

## License

No license has been selected for this repository yet.
