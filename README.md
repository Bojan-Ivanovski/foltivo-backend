# Foltivo Backend

Go backend for **Foltivo**, a Markdown-first workspace for connected knowledge,
writing and collaboration. The selected product domain is **foltivo.com**.

This repository contains a Go REST API, local PostgreSQL infrastructure and an
embedded Goose schema migration command. Authentication is not implemented yet.

## Development

Install the Go version specified in [go.mod](go.mod), then work from this directory.
The module uses `github.com/Bojan-Ivanovski/foltivo-backend`. Follow the
[database development guide](docs/dev/database.md) for configuration, migration
authoring, production expectations and rollback/recovery.

Set up local PostgreSQL and start the API:

```sh
cp .env.example .env
# Edit .env: replace the local password in POSTGRES_PASSWORD and DATABASE_URL.
docker compose up -d --wait
set -a
. ./.env
set +a
go run ./cmd/migrate up
go run ./cmd/api
```

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
