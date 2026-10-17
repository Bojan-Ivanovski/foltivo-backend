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
