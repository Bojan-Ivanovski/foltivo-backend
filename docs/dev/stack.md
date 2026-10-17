# Backend stack

## Confirmed

- **Go** is the backend application language; the required toolchain is recorded
  in [go.mod](../../go.mod).
- The frontend/backend API boundary uses **REST**.
- The module is `github.com/Bojan-Ivanovski/foltivo-backend`.
- Product name: **Foltivo**. Intended public domain: **foltivo.com**. This does not
  establish deployment, API subdomains, mail addresses or authentication callbacks.

## Current state

The repository contains a minimal standard-library HTTP server in cmd/api.
Run `go run ./cmd/api`; `GET /health` returns HTTP 200 and
`{"status":"ok"}`. HTTP_ADDR overrides the default :8080 listen address.
The endpoint reports process liveness, not dependency readiness. No database,
external Go dependencies or deployment are implemented. No go.sum is needed
until dependencies require it.

## Pending decisions

- Database engine, driver and migration approach: backend #2. Goose is a
  candidate, not an installed/selected dependency.
- Authentication libraries/service composition: backend #3. The application and
  authentication design must respect the developer's Go direction; no Better
  Auth/Node service is selected. Factor, recovery and assurance contracts still
  require analysis.
- The initial server uses net/http and its ServeMux. Additional framework,
  query-layer, job, storage, live collaboration and hosting choices remain open.

Use gofmt for Go source when introduced. Add dependencies, executable commands
and CI checks only when their scope and prerequisites are established; do not
claim a server or test suite exists because a Go module has been initialized.
