# Backend ticket hierarchy and starting order

| Issue | Purpose | Parent |
| --- | --- | --- |
| [#1](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/1) | v0.1.0 release objective | None |
| [#2](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/2) | Versioned database schema migrations | #1 |
| [#3](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/3) | Go account authentication and sessions | #1 |

Backend #2 selects PostgreSQL 18, pgx and embedded Goose migrations. Backend #3
selects Go-owned authentication with durable opaque sessions, email lifecycle,
TOTP/recovery and verified passkeys. These foundations are present on develop;
use them instead of adding a parallel authentication service.

| Follow-up | Purpose | Parent | Frontend integration |
| --- | --- | --- | --- |
| [#9](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/9) | Verified email changes | #1 | foltivo-frontend #67 |
| [#10](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/10) | Session metadata and bulk revocation | #1 | foltivo-frontend #68 |
| [#11](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/11) | Optional GitHub/Google linked identities | #1 | foltivo-frontend #69 |
| [#12](https://github.com/Bojan-Ivanovski/foltivo-backend/issues/12) | Thirty-day account closure and recovery | #1 | foltivo-frontend #70 |

The follow-ups are prepared on an issue branch; implementation does not imply
commit, push, review or delivery. Frontend account settings #11 and account
management #41 remain coordination parents until their delivered scope is complete.
Provider credentials are deployment prerequisites. Organization/content disposition
must be integrated before those presently unimplemented resources are enabled.

Default independent release work to #1; create bounded children for an existing
outcome where needed. Ordinary group parents use the work-item template. Use
native GitHub dependencies for genuine implementation prerequisites, not every
related issue. No additional delivery groups have been created here.

Frontend issue numbers are a separate namespace. Link cross-repository work with
full repository references or URLs. Frontend #7 and its integration slices need
Go-aware coordination; do not blindly copy their earlier TypeScript auth
recommendation or duplicate backend services in the frontend. Keep changes on the
owning issue and split substantial work during analysis before implementation.

Backend #13 groups the integrated account-completion delivery for #9–#12.
