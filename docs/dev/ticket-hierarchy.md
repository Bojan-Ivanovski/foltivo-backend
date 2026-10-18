# Backend ticket hierarchy and starting order

Backend #18 is the Rust parity migration under epic #1. It replaces the Go
implementation in the same repository using SeaORM and SeaORM Migration.

| Issue | Responsibility | Parent |
| --- | --- | --- |
| #1 | v0.1.0 release | None |
| #18 | Rust migration preserving current delivered behavior | #1 |
| #15 | Database artifact organization, adapted for Rust | #1 |
| #16 | Visual database design and manual synchronization workflow | #1 |
| #17 | Historical Go/Ent evaluation, superseded by #18 | #1 |

The delivered account/authentication scope from #2–#13 is the migration baseline,
not new functionality. Frontend integration remains in Bojan-Ivanovski/foltivo-frontend.
Provider credentials remain deployment prerequisites. Organization/content
features are not invented by the rewrite; disposition and live blockers must be
integrated before those resources are enabled.

Use native parent links. Default independent work to epic #1 and use bounded
children for delivery groups when scoped. Do not confuse frontend/backend issue
numbers. Commit/push authorization remains separate from implementation.
