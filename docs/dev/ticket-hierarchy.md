# Backend ticket hierarchy and starting order

| Issue | Purpose | Parent |
| --- | --- | --- |
| [#1](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/1) | v0.1.0 release objective | None |
| [#2](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/2) | Versioned database schema migrations | #1 |
| [#3](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/3) | Go account authentication and sessions | #1 |

Backend #2 selects PostgreSQL 18, pgx and embedded Goose migrations; implementation
and verification are prepared for review. Complete its delivery before persistent
authentication implementation in #3. Authentication analysis can proceed alongside
migration work. The identity/session contract discussion does not need to wait
for migration delivery. No authentication library/provider is selected yet.

Default independent release work to #1; create bounded children for an existing
outcome where needed. Ordinary group parents use the work-item template. Use
native GitHub dependencies for genuine implementation prerequisites, not every
related issue. No additional delivery groups have been created here.

Frontend issue numbers are a separate namespace. Link cross-repository work with
full repository references or URLs. Frontend #7 and its integration slices need
Go-aware coordination; do not blindly copy their earlier TypeScript auth
recommendation or duplicate backend services in the frontend. Keep changes on the
owning issue and split substantial work during analysis before implementation.
