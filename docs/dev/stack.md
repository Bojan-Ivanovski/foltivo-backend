# Backend stack

## Confirmed

Backend #18 selects **Rust**, **SeaORM** and **SeaORM Migration**, superseding Go,
pgx, Goose execution and the Ent adoption decision. The API boundary remains
**REST**. This is the same foltivo-backend repository and PostgreSQL database.

- Rust Cargo workspace: root application plus `database/` crate.
- Axum HTTP boundary on Tokio, with graceful shutdown and worker cancellation.
- PostgreSQL 18; local Compose pins the existing postgres:18.6-bookworm image.
- SeaORM entities/ActiveModels for persistence, with explicit PostgreSQL through
  SeaORM for conditional transitions and lock-sensitive operations.
- SeaORM Migration executes registered, embedded SQL through an explicit CLI;
  no API-startup migrations. A one-time adopter handles existing Goose history.
- Argon2id, purpose-bound AES-256-GCM secrets, opaque PostgreSQL-backed sessions,
  TOTP/recovery codes, WebAuthn and application-owned account lifecycle.
- Lettre SMTP, encrypted durable email outbox and bounded retry worker.
- Optional existing-account GitHub/Google identity linking/login, PKCE, verified
  Google identity tokens and browser-bound coordinated completion.

Product name is Foltivo; intended domain is foltivo.com. This does not select
hosting, API subdomains, production mail addresses or deployment topology.

## Design workflow

Keep database design review and manual synchronization of diagrams, SeaORM
entities and reviewed migrations. Automatic diagram-to-model/SQL generation is
deferred. See [database design](database-design.md), [database operations](database.md)
and [migration notes](rust-migration.md).

## Delivery status

The initial Rust replacement was implemented without validation or new tests.
Subsequent authorized local startup compiled successfully; health, database
readiness and frontend-proxied session bootstrap returned 200. These observations
do not prove full parity. Proper automated coverage is tracked in #19; no
performance result is claimed.

Resource authorization, content persistence and live collaboration are separate
future product deliveries. Rust does not select their protocols or architecture.
