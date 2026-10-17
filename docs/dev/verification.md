# Verification

Run these checks from the repository root. Use the Go toolchain specified by
`go.mod`.

## Source and build checks

```sh
unformatted=$(gofmt -l $(git ls-files '*.go'))
if [ -n "$unformatted" ]; then
  printf 'Go files need gofmt:\n%s\n' "$unformatted"
  exit 1
fi
go vet ./...
```

## Tests with PostgreSQL

The CI workflow starts PostgreSQL 18.6 and runs the race-enabled suite with
`TEST_DATABASE_URL` set. That variable is required for the migration integration
tests; if it is unset, those tests skip and only the unit tests run. To match CI
locally, start a dedicated PostgreSQL 18.6 database whose test role can create
schemas, then set the explicit test URL and run:

```sh
TEST_DATABASE_URL='postgres://foltivo_test:replace-this@127.0.0.1:5432/foltivo_test?sslmode=disable' go test -race -count=1 ./...
```

Then build all packages:

```sh
go build ./...
```

For a local database already configured through `DATABASE_URL`, export that URL
as `TEST_DATABASE_URL` only if it points to an isolated test database:

```sh
TEST_DATABASE_URL="$DATABASE_URL" go test -race -count=1 ./...
```

Integration tests create uniquely named temporary schemas and remove them during
cleanup. Keep test credentials separate from development and production. Never
point this command at production.

## Authentication and browser integration

The real-DB suite covers account/session assurance, Origin and CSRF, token
expiry/purpose/replay, mail retries, MFA enrollment/recovery, passkey ceremony
boundaries and trusted proxy address isolation. TOTP acceptance consumes its
step across sessions. Password resets preserve factors and revoke sessions.
No trusted SQL fixture is an application verification bypass.

The frontend repository's `docs/dev/authentication.md` describes the opt-in live
Chromium test. Use `APP_ORIGIN=http://localhost:4173` here, PostgreSQL and Mailpit,
then run that test from the frontend checkout. It exercises registration, real
email delivery and verification, profile persistence, TOTP/recovery-code replay,
CTAP2 passkey enrollment and user verification, password recovery preserving MFA,
logout, CSRF and protected routes. A separate two-tab browser regression verifies
session-cookie coordination. Hosted frontend CI intentionally runs the offline
suite; do not claim hosted full-stack verification from a local browser pass.

Also verify physical database/API restarts retain an active session and user,
while a database outage gives liveness 200 and readiness 503 before recovery.
Keep any fixture cookies or keys private and ignored.

For dependency security checks:

```sh
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Review all reported results. The milestone scan found no vulnerable imported
packages or reachable symbols; it reported GO-2026-5932 for the unused OpenPGP
package within x/crypto, with no available fixed module version. This application
does not import OpenPGP. Production still requires real TLS termination, explicit
trusted proxy CIDRs, database TLS, SMTP TLS and securely retained encryption keys;
local Mailpit/HTTP checks do not constitute a production deployment.
