# Foltivo Backend

Go backend for **Foltivo**, a Markdown-first workspace for connected knowledge,
writing and collaboration. The selected product domain is **foltivo.com**.

This repository contains a minimal Go HTTP server and repository guidance.
No database, authentication provider or deployment is implemented yet.

## Development

Install the Go version specified in [go.mod](go.mod), then work from this directory.
The module uses `github.com/Bojan-Ivanovski/foltivo-backend` and has no external
Go dependencies. A `go.sum` will be generated when dependencies require one.

Start the API:

```sh
go run ./cmd/api
```

`GET http://localhost:8080/health` returns HTTP 200 with JSON:

```json
{"status":"ok"}
```

This is a process liveness endpoint; it does not check database or external-service
readiness. Set `HTTP_ADDR` to override the default `:8080`, for example:

```sh
HTTP_ADDR=127.0.0.1:8081 go run ./cmd/api
```

The intended application boundary is a Go REST API. Provider, database,
authorization and live collaboration designs require separate analysis and
selection before implementation.

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
