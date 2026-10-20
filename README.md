# Foltivo Backend

Rust backend for **Foltivo**, a Markdown-first workspace for connected knowledge,
writing and collaboration. The selected domain is **foltivo.com**.

This repository contains the REST API, PostgreSQL infrastructure, SeaORM entities,
SeaORM Migration command and application-owned authentication. It replaces the
Go implementation within the same repository; Git retains the original source.

## Development

Install Rust through rustup, Docker with Compose, and native WebAuthn build
prerequisites (on Debian/Ubuntu: `pkg-config` and `libssl-dev`). The toolchain is
configured in [rust-toolchain.toml](rust-toolchain.toml).

```sh
cp .env.example .env
# Edit .env: set a local database password and a persistent
# AUTH_ENCRYPTION_KEY (openssl rand -base64 32).
docker compose up -d --wait
set -a
. ./.env
set +a
# Fresh database:
cargo run --bin migrate -- up
cargo run --bin api
```

For a database previously migrated by Go/Goose, stop the old API/workers and run
`cargo run --bin migrate -- adopt-goose` once before `up`. This transfers the
applied history without recreating tables. Keep the existing encryption key.
See [database operations](docs/dev/database.md) and
[Rust migration notes](docs/dev/rust-migration.md).

The frontend continues using its existing REST contract and Vite proxy.
APP_ORIGIN must match its browser origin. Local email is captured at
http://localhost:8025. SMTP failures remain in the encrypted outbox for retry.

`GET /health` returns `200 {"status":"ok"}` independently of PostgreSQL.
`GET /ready` returns 200 when PostgreSQL responds and 503 otherwise. The API never
applies migrations. HTTP_ADDR defaults to `:8080`; SIGINT/SIGTERM initiate graceful
shutdown. Docker Compose retains the PostgreSQL volume when stopped.

The initial migration was implemented without tests or validation, as requested.
The subsequently authorized local startup compiled successfully; health, database
readiness and session bootstrap through the frontend returned 200. Full behavioral
parity has not been verified. Automated coverage is tracked in
[backend #19](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/19).
See the [Rust testing guide](docs/dev/testing.md) for the selected test framework,
disposable PostgreSQL fixtures, and the workspace test command.

## Product and work tracking

- [Frontend repository](https://github.com/Bojan-Ivanovski/foltivo-frontend)
- [Rust migration #18](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/18)
- [Development process](docs/dev/process.md)
- [Stack](docs/dev/stack.md)
- [Authentication](docs/dev/authentication.md)
- [REST contract](docs/api/authentication.md)
- [Contributing](CONTRIBUTING.md)

User Libraries support independent personal work; Organization Libraries support
shared work. Libraries own Folios; optional Books reference Folios without
conferring access. Working revisions, Git commits and published versions are
separate identities. Content features and resource authorization remain separate
deliveries from the existing account/authentication backend.

## License

No license has been selected for this repository yet.
