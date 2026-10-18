# Contributing to Foltivo Backend

Start with [the development process](docs/dev/process.md) and
[the current stack](docs/dev/stack.md). Use the repository issue forms and native
parents/dependencies. Keep work bounded, attach findings and solution options
when analysis is requested, and let the developer select the solution.

Follow [the workflow](docs/dev/workflow.md) for issue branches, exact Type: label
commit subjects and the required **Summary** commit body. Do not commit or push
without explicit authorization. Record only verification actually performed.

The backend is Rust with SeaORM and SeaORM Migration. Keep database artifacts
under `database/` and process documentation under `docs/dev`. Maintain entity,
diagram and migration consistency manually. Keep secrets and build outputs out
of Git. Document configuration using placeholders only.

Use rustfmt for formatting when authorized; do not add or run tests without a
request. #18 was explicitly implemented without review or validation and has no
claimed verified parity. See [verification status](docs/dev/verification.md).

For defects, include reproduction steps and impact. A private security reporting
channel has not been configured; do not put credentials, private data or exploit
details into public issues. No repository license has been selected yet.
